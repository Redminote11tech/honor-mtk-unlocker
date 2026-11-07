import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// One async event emitted by the backend.
class BackendEvent {
  final String kind; // 'log' | 'progress'
  final Map<String, dynamic> data;

  BackendEvent(this.kind, this.data);
}

/// Thin client for the Rust sidecar (`honor_mtk_unlocker serve`),
/// newline-delimited JSON on stdin/stdout.
class HonorBackend {
  Process? _proc;
  final Map<int, Completer<Map<String, dynamic>>> _pending = {};
  final _events = StreamController<BackendEvent>.broadcast();
  int _nextId = 1;
  bool _closed = false;

  Stream<BackendEvent> get events => _events.stream;

  String _resolveBinary() {
    final env = Platform.environment['HONOR_MTK_UNLOCKER_BIN'];
    if (env != null && env.isNotEmpty) return env;
    final rel = Platform.isWindows
        ? '..\\core\\target\\debug\\honor_mtk_unlocker.exe'
        : '../core/target/debug/honor_mtk_unlocker';
    if (File(rel).existsSync()) return rel;
    return 'honor_mtk_unlocker';
  }

  Future<void> start({required String outDir}) async {
    final bin = _resolveBinary();
    _proc = await Process.start(bin, ['serve', '--out', outDir]);
    _proc!.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen(_onLine);
    _proc!.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((l) {
      if (l.trim().isNotEmpty) {
        _events.add(BackendEvent('log', {'level': 'stderr', 'message': l}));
      }
    });
    _proc!.exitCode.then((_) {
      _closed = true;
      for (final c in _pending.values) {
        if (!c.isCompleted) c.completeError(StateError('backend exited'));
      }
      _pending.clear();
    });
  }

  void _onLine(String line) {
    if (line.trim().isEmpty) return;
    Map<String, dynamic>? msg;
    try {
      msg = jsonDecode(line) as Map<String, dynamic>;
    } catch (_) {
      return;
    }
    if (msg.containsKey('event')) {
      final kind = msg['event'] as String;
      _events.add(BackendEvent(kind, msg));
      return;
    }
    final id = msg['id'] as int?;
    if (id == null) return;
    final c = _pending.remove(id);
    if (c == null) return;
    if (msg['ok'] == true) {
      c.complete((msg['result'] as Map<String, dynamic>?) ?? {});
    } else {
      c.completeError(StateError('${msg['error'] ?? 'unknown backend error'}'));
    }
  }

  Future<Map<String, dynamic>> call(String cmd, [Map<String, dynamic> args = const {}]) async {
    if (_closed || _proc == null) {
      throw StateError('backend not running');
    }
    final id = _nextId++;
    final c = Completer<Map<String, dynamic>>();
    _pending[id] = c;
    _proc!.stdin.writeln(jsonEncode({'id': id, 'cmd': cmd, 'args': args}));
    return c.future.timeout(const Duration(minutes: 10));
  }

  Future<void> stop() async {
    _closed = true;
    _proc?.kill();
    await _events.close();
  }
}

// Typed helpers ---------------------------------------------------------------

class DeviceInfo {
  final String serial, model, product, sdk, abi, slot;
  final bool supported;
  final bool? bootloaderUnlocked;
  final bool rootPresent;
  final String platform, socModel;
  final bool isMtk;
  DeviceInfo.fromJson(Map<String, dynamic> j)
      : serial = j['serial'] as String? ?? '',
        model = j['model'] as String? ?? '',
        product = j['product'] as String? ?? '',
        sdk = j['sdk'] as String? ?? '',
        abi = j['abi'] as String? ?? '',
        slot = j['slot'] as String? ?? '',
        supported = (j['supported'] as bool?) ?? false,
        bootloaderUnlocked = j['bootloader_unlocked'] as bool?,
        rootPresent = (j['root_present'] as bool?) ?? false,
        platform = j['platform'] as String? ?? '',
        socModel = j['soc_model'] as String? ?? '',
        isMtk = (j['is_mtk'] as bool?) ?? false;
}

class PartitionInfo {
  final String name, blockPath;
  final bool recognized;
  PartitionInfo.fromJson(Map<String, dynamic> j)
      : name = j['name'] as String? ?? '',
        blockPath = j['block_path'] as String? ?? '',
        recognized = (j['recognized'] as bool?) ?? false;
}

class PartitionRead {
  final String? name, path;
  final int bytes;
  final String sha256, savedAs;
  final Map<String, dynamic> parsed;
  PartitionRead.fromJson(Map<String, dynamic> j)
      : name = j['name'] as String?,
        path = j['path'] as String?,
        bytes = j['bytes'] as int? ?? 0,
        sha256 = j['sha256'] as String? ?? '',
        savedAs = j['saved_as'] as String? ?? '',
        parsed = (j['parsed'] as Map<String, dynamic>?) ?? {};
}

class UnlockPlan {
  final Map<String, dynamic> seccfg;
  final Map<String, dynamic> lkA, lkB;
  final List<String> steps, warnings, whyNot;
  final bool proceed;
  UnlockPlan.fromJson(Map<String, dynamic> j)
      : seccfg = (j['seccfg'] as Map<String, dynamic>?) ?? {},
        lkA = (j['lk_a'] as Map<String, dynamic>?) ?? {},
        lkB = (j['lk_b'] as Map<String, dynamic>?) ?? {},
        steps = List<String>.from(j['steps'] as List? ?? []),
        warnings = List<String>.from(j['warnings'] as List? ?? []),
        whyNot = List<String>.from(j['why_not'] as List? ?? []),
        proceed = (j['proceed'] as bool?) ?? false;
}
