import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import '../services/honor_backend.dart';

enum StepStatus { pending, active, done, error }

class _StepState {
  final String id;
  final String label;
  StepStatus status;
  String detail;

  _StepState(this.id, this.label)
      : status = StepStatus.pending,
        detail = '';
}

class WizardScreen extends StatefulWidget {
  const WizardScreen({super.key});

  @override
  State<WizardScreen> createState() => _WizardScreenState();
}

class _WizardScreenState extends State<WizardScreen>
    with SingleTickerProviderStateMixin {
  final _backend = HonorBackend();
  late final AnimationController _pulse;

  bool _backendReady = false;
  bool _phase = false; // false = welcome, true = wizard
  bool _running = false;
  String _phaseLabel = '';
  String _outDir = '';
  String _apkPath = '';
  String _terminal = ''; // '', 'unlocked', 'done', 'aborted'
  String _error = '';
  DeviceInfo? _device;
  Map<String, dynamic>? _report;
  final List<_StepState> _steps = [];

  @override
  void initState() {
    super.initState();
    final home = Platform.environment['HOME'] ?? '.';
    _outDir = '$home/honor-mtk-unlocker-output';
    _apkPath = Platform.environment['HONOR_DFROOT_APK'] ?? 'vendor/DFRoot.apk';
    _pulse = AnimationController(vsync: this, duration: const Duration(milliseconds: 1100))
      ..repeat(reverse: true);
    _bootBackend();
    Timer(const Duration(milliseconds: 3200), () {
      if (mounted) setState(() => _phase = true);
    });
  }

  Future<void> _bootBackend() async {
    try {
      await _backend.start(outDir: _outDir);
      await _backend.call('ping');
      if (mounted) setState(() => _backendReady = true);
    } catch (_) {
      if (mounted) {
        setState(() {
          _error = 'Could not start the Rust core (honor_mtk_unlocker). '
              'Run it from a terminal to see the error.';
          _phase = true;
        });
      }
    }
  }

  @override
  void dispose() {
    _pulse.dispose();
    _backend.stop();
    super.dispose();
  }

  // ---- step tracking ------------------------------------------------------

  _StepState _step(String id, String label) {
    for (final s in _steps) {
      if (s.id == id) return s;
    }
    final s = _StepState(id, label);
    _steps.add(s);
    return s;
  }

  void _begin(String id, String label, String detail) {
    setState(() {
      _phaseLabel = detail;
      for (final s in _steps) {
        s.status = (s.id == id) ? StepStatus.active : s.status;
      }
      final s = _step(id, label);
      s.status = StepStatus.active;
      s.detail = detail;
    });
  }

  void _done(String id, [String? detail]) {
    setState(() {
      final s = _step(id, '');
      s.status = StepStatus.done;
      if (detail != null) s.detail = detail;
    });
  }

  void _fail(String id, String detail) {
    setState(() {
      final s = _step(id, '');
      s.status = StepStatus.error;
      s.detail = detail;
    });
  }

  // ---- dialogs ------------------------------------------------------------

  Future<bool?> _notice({
    required String title,
    required String body,
    String ok = 'OK',
    String? cancel,
    int okAfterSeconds = 0,
  }) {
    return showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (_) => _NoticeDialog(
        title: title,
        body: body,
        okLabel: ok,
        cancelLabel: cancel,
        okAfterSeconds: okAfterSeconds,
      ),
    );
  }

  Future<String?> _askApk() {
    final c = TextEditingController(text: _apkPath);
    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        title: const Text('DFRoot.apk'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Path to the DFRoot.apk the tool should install.'),
            const SizedBox(height: 12),
            TextField(
              controller: c,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                labelText: 'APK path',
              ),
              onSubmitted: (v) => Navigator.pop(ctx, v.trim()),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, c.text.trim()),
            child: const Text('Use'),
          ),
        ],
      ),
    );
  }

  // ---- flow ---------------------------------------------------------------

  Future<void> _run() async {
    if (_running) return;
    _running = true;
    setState(() {
      _steps.clear();
      _terminal = '';
      _error = '';

      _report = null;
    });

    try {
      await _checks();
      if (_terminal.isNotEmpty) return; // already unlocked / cancelled
      await _rootPhase();
      if (_terminal.isNotEmpty) return; // cancelled
      await _dumpPhase();
      await _patchConfirmPhase();
      if (_terminal.isNotEmpty) return; // cancelled
      await _writePhase();
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = '$e';
        });
        await _notice(title: 'Error', body: '$e', ok: 'OK');
      }
    } finally {
      if (mounted) setState(() => _running = false);
    }
  }

  Future<void> _checks() async {
    _begin('output', 'Output folder', 'Verifying output folder exists…');
    await _ensureBackend();
    final out = await _backend.call('ensure_outdir');
    if (out['created'] == true) {
      await _notice(title: 'Notice', body: 'Creating output_folder in home.');
      _done('output', 'Created $_outDir');
    } else {
      _done('output', _outDir);
    }

    _begin('device', 'Device', 'Verifying device connection…');
    while (true) {
      DeviceInfo? info;
      try {
        info = DeviceInfo.fromJson(await _backend.call('check'));
      } catch (_) {}
      if (info != null && info.supported) {
        _device = info;
        _done('device', '${info.model} connected');
        break;
      }
      await _notice(title: 'Notice', body: 'Connect your honor device to continue');
    }

    if (_device!.bootloaderUnlocked == true) {
      await _notice(title: 'Notice', body: 'Your bootloader is already unlocked!');
      setState(() => _terminal = 'unlocked');
      return;
    }
  }

  Future<void> _rootPhase() async {
    if (_terminal.isNotEmpty) return; // already stopped
    final already = _device?.rootPresent ?? false;

    if (!already) {
      final go = await _notice(
        title: 'Notice',
        body: 'Attempting temp-root',
        ok: 'OK',
        cancel: 'Cancel',
      );
      if (go != true) {
        setState(() => _terminal = 'aborted');
        return;
      }
    }

    _begin('dfroot', 'DFRoot', 'Preparing DFRoot…');
    if (_apkPath.isEmpty || !File(_apkPath).existsSync()) {
      final p = await _askApk();
      if (p == null || p.isEmpty) {
        setState(() => _terminal = 'aborted');
        return;
      }
      _apkPath = p;
    }

    await _backend.call('root_prepare', {'apk': _apkPath});
    await _notice(
      title: 'Notice',
      body: 'Click launch root.',
      okAfterSeconds: 5,
    );

    var rooted = false;
    for (var attempt = 0; attempt < 3 && !rooted; attempt++) {
      try {
        await _backend.call('root_wait');
        rooted = true;
      } catch (_) {
        if (attempt < 2) {
          await _notice(
            title: 'Notice',
            body: 'Root not achieved yet — tap LAUNCH ROOT again.',
          );
        }
      }
    }
    if (!rooted) {
      throw StateError('Temp root could not be achieved after 3 attempts.');
    }
    _done('dfroot', 'Root verified (uid 0)');
  }

  Future<void> _dumpPhase() async {
    _begin('dump', 'Dump', 'All checks done, dumping LK and seccfg.');
    final names = ['seccfg', 'lk_a', 'lk_b'];
    for (final name in names) {
      await _backend.call('read_partition', {'name': name, 'max_mb': 8});
    }
    _done('dump', 'LK + seccfg dumped and parsed');
  }

  Future<void> _patchConfirmPhase() async {
    if (_terminal.isNotEmpty) return; // already stopped
    _begin('patch', 'Patch', 'Patching LK and seccfg');
    final plan = UnlockPlan.fromJson(await _backend.call('unlock_plan'));

    if (!plan.proceed) {
      _fail('patch', plan.whyNot.join('; '));
      throw StateError('Cannot patch: ${plan.whyNot.join('; ')}');
    }
    _done('patch', 'Patch verified for ${plan.lkA['variant'] ?? 'build'}');

    final body = StringBuffer('This action cannot be reversed once ran, confirm the '
        'LK and seccfg write.\n\n');
    body.writeAll(plan.warnings, '\n');
    final confirm = await _notice(
      title: 'Warning',
      body: body.toString(),
      ok: 'OK',
      cancel: 'Cancel',
      okAfterSeconds: 5,
    );
    if (confirm != true) {
      setState(() => _terminal = 'aborted');
    }
  }

  Future<void> _writePhase() async {
    _begin('write', 'Write', 'Writing LK and seccfg');
    final report = await _backend.call('unlock_execute');
    _report = report;
    _done('write', 'Write completed');
    _begin('readback', 'Readback', 'Write has been completed, readback verification');
    await Future.delayed(const Duration(milliseconds: 400));
    _done('readback', 'Readback verified');
    setState(() => _terminal = 'done');
  }

  Future<void> _ensureBackend() async {
    if (!_backendReady) {
      await _bootBackend();
      if (!_backendReady) {
        throw StateError(_error);
      }
    }
  }

  // ---- UI -----------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: AnimatedSwitcher(
        duration: const Duration(milliseconds: 600),
        child: _phase ? _buildWizard(context) : _buildWelcome(context),
      ),
    );
  }

  Widget _buildWelcome(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      key: const ValueKey('welcome'),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [scheme.primaryContainer, scheme.tertiaryContainer],
        ),
      ),
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ScaleTransition(
              scale: Tween(begin: 0.9, end: 1.08).animate(
                CurvedAnimation(parent: _pulse, curve: Curves.easeInOut),
              ),
              child: Container(
                width: 112,
                height: 112,
                decoration: BoxDecoration(
                  color: scheme.primary.withValues(alpha: 0.14),
                  shape: BoxShape.circle,
                ),
                child: Icon(Icons.lock_open_rounded, size: 54, color: scheme.primary),
              ),
            ),
            const SizedBox(height: 28),
            Text(
              'Welcome to Honor MTK Unlocker',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.w700,
                    color: scheme.onPrimaryContainer,
                  ),
            ),
            const SizedBox(height: 10),
            Text(
              'preparing…',
              style: TextStyle(color: scheme.onPrimaryContainer.withValues(alpha: 0.7)),
            ),
            const SizedBox(height: 24),
            SizedBox(
              width: 24,
              height: 24,
              child: CircularProgressIndicator(strokeWidth: 2.6, color: scheme.primary),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildWizard(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(Icons.lock_open_rounded, color: scheme.primary),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'Honor MTK Unlocker',
                    style: Theme.of(context).textTheme.titleLarge?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            _CurrentPhaseCard(
              label: _phaseLabel,
              busy: _running,
              error: _error,
            ),
            const SizedBox(height: 12),
            Expanded(
              child: _steps.isEmpty && !_running
                  ? _StartCard(onStart: _run)
                  : ListView(
                      children: [
                        for (final s in _steps) _StepTile(state: s),
                        const SizedBox(height: 12),
                        if (_terminal == 'done' && _report != null)
                          _DoneCard(report: _report!, onRestart: _reset)
                        else if (_terminal == 'unlocked')
                          _TerminalCard(
                            icon: Icons.verified_outlined,
                            title: 'Bootloader already unlocked',
                            message: 'Nothing to do. Enjoy your device!',
                            onRestart: _reset,
                          )
                        else if (_terminal == 'aborted')
                          _TerminalCard(
                            icon: Icons.stop_circle_outlined,
                            title: 'Cancelled',
                            message: 'No changes were written.',
                            onRestart: _reset,
                          )
                        else if (_error.isNotEmpty && !_running)
                          _TerminalCard(
                            icon: Icons.error_outline,
                            title: 'Stopped',
                            message: _error,
                            onRestart: _reset,
                          ),
                      ],
                    ),
            ),
          ],
        ),
      ),
    );
  }

  void _reset() {
    setState(() {
      _steps.clear();
      _terminal = '';
      _error = '';

      _report = null;
      _phaseLabel = '';
    });
    _run();
  }
}

// ---------------------------------------------------------------------------

class _CurrentPhaseCard extends StatelessWidget {
  const _CurrentPhaseCard({required this.label, required this.busy, required this.error});

  final String label;
  final bool busy;
  final String error;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            SizedBox(
              width: 26,
              height: 26,
              child: busy
                  ? CircularProgressIndicator(strokeWidth: 2.6, color: scheme.primary)
                  : Icon(error.isNotEmpty ? Icons.error_outline : Icons.check_circle_outline,
                      color: error.isNotEmpty ? scheme.error : scheme.primary),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Text(
                label.isEmpty ? 'Ready — press Start to begin.' : label,
                style: TextStyle(
                  fontWeight: FontWeight.w600,
                  color: error.isNotEmpty ? scheme.error : scheme.onSurface,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _StartCard extends StatelessWidget {
  const _StartCard({required this.onStart});

  final VoidCallback onStart;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: FilledButton.icon(
        onPressed: onStart,
        icon: const Icon(Icons.play_arrow),
        label: const Text('Start'),
        style: FilledButton.styleFrom(minimumSize: const Size(180, 52)),
      ),
    );
  }
}

class _StepTile extends StatelessWidget {
  const _StepTile({required this.state});

  final _StepState state;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final (IconData icon, Color color) = switch (state.status) {
      StepStatus.pending => (Icons.circle_outlined, scheme.outlineVariant),
      StepStatus.active => (Icons.hourglass_top, scheme.primary),
      StepStatus.done => (Icons.check_circle, scheme.primary),
      StepStatus.error => (Icons.error_outline, scheme.error),
    };
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: Icon(icon, color: color),
        title: Text(
          state.label.isEmpty ? state.detail : state.label,
          style: const TextStyle(fontWeight: FontWeight.w600),
        ),
        subtitle: state.detail.isNotEmpty && state.detail != state.label
            ? Text(state.detail, style: const TextStyle(fontSize: 12))
            : null,
      ),
    );
  }
}

class _DoneCard extends StatelessWidget {
  const _DoneCard({required this.report, required this.onRestart});

  final Map<String, dynamic> report;
  final VoidCallback onRestart;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final writes = (report['writes'] as List? ?? []);
    final backups = (report['backups'] as List? ?? []);
    return Card(
      color: scheme.primaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.restart_alt_rounded, color: scheme.onPrimaryContainer, size: 34),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Reboot your device for unlock to take place',
                    style: TextStyle(
                      fontWeight: FontWeight.w700,
                      fontSize: 16,
                      color: scheme.onPrimaryContainer,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Text('Written: ${writes.join(', ')}',
                style: TextStyle(color: scheme.onPrimaryContainer)),
            Text('Backups (restore if anything fails):',
                style: TextStyle(color: scheme.onPrimaryContainer)),
            for (final b in backups.take(5))
              Text('  • $b', style: TextStyle(color: scheme.onPrimaryContainer, fontSize: 12)),
            const SizedBox(height: 12),
            Text(
              'Do NOT update via OTA — it overwrites the LK. Do NOT relock.',
              style: TextStyle(color: scheme.onPrimaryContainer, fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 14),
            OutlinedButton(
              onPressed: onRestart,
              child: const Text('Start over'),
            ),
          ],
        ),
      ),
    );
  }
}

class _TerminalCard extends StatelessWidget {
  const _TerminalCard({
    required this.icon,
    required this.title,
    required this.message,
    required this.onRestart,
  });

  final IconData icon;
  final String title;
  final String message;
  final VoidCallback onRestart;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            Icon(icon, size: 44, color: scheme.primary),
            const SizedBox(height: 12),
            Text(title,
                style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 16)),
            const SizedBox(height: 6),
            Text(message, textAlign: TextAlign.center),
            const SizedBox(height: 14),
            OutlinedButton(onPressed: onRestart, child: const Text('Start over')),
          ],
        ),
      ),
    );
  }
}

class _NoticeDialog extends StatefulWidget {
  const _NoticeDialog({
    required this.title,
    required this.body,
    required this.okLabel,
    this.cancelLabel,
    this.okAfterSeconds = 0,
  });

  final String title;
  final String body;
  final String okLabel;
  final String? cancelLabel;
  final int okAfterSeconds;

  @override
  State<_NoticeDialog> createState() => _NoticeDialogState();
}

class _NoticeDialogState extends State<_NoticeDialog> {
  int _left = 0;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    if (widget.okAfterSeconds > 0) {
      _left = widget.okAfterSeconds;
      _timer = Timer.periodic(const Duration(seconds: 1), (t) {
        if (_left <= 1) {
          t.cancel();
        }
        setState(() => _left = _left > 0 ? _left - 1 : 0);
      });
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final enabled = _left == 0;
    return AlertDialog(
      icon: Icon(Icons.info_outline, color: scheme.primary, size: 36),
      title: Text(widget.title),
      content: Text(widget.body),
      actions: [
        if (widget.cancelLabel != null)
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(widget.cancelLabel!),
          ),
        FilledButton(
          onPressed: enabled ? () => Navigator.pop(context, true) : null,
          child: Text(enabled ? widget.okLabel : '${widget.okLabel} ($_left)'),
        ),
      ],
    );
  }
}
