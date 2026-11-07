import 'package:flutter/material.dart';

import 'theme.dart';
import 'wizard/wizard_screen.dart';

class HonorToolApp extends StatelessWidget {
  const HonorToolApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Honor MTK Unlocker',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(),
      home: const WizardScreen(),
    );
  }
}
