import 'dart:convert';
import 'package:flutter/foundation.dart';
import '../models/vault_info.dart';
import 'vault_channel.dart';

/// VaultRegistry - Multi-Vault Management Service
/// 
/// Manages the collection of vaults on the device, supporting up to
/// [maxVaults] (25) independent encrypted vaults. Each vault has its
/// own password and encrypted title.
/// 
/// Features:
/// - List all vaults with metadata
/// - Create new vaults with encrypted titles
/// - Import vault files from external storage
/// - Delete vaults securely
/// - Reveal/update vault titles (requires authentication)
/// 
/// The registry itself is stored unencrypted (only contains metadata),
/// while vault titles are stored encrypted inside each vault file.
class VaultRegistry extends ChangeNotifier {
  static const int maxVaults = 25;
  
  List<VaultInfo> _vaults = [];
  bool _isLoading = true;
  String? _error;
  String? _currentVaultId;

  List<VaultInfo> get vaults => List.unmodifiable(_vaults);
  bool get isLoading => _isLoading;
  String? get error => _error;
  String? get currentVaultId => _currentVaultId;
  bool get canAddVault => _vaults.length < maxVaults;
  int get vaultCount => _vaults.length;

  /// Load vault registry from device
  Future<void> load() async {
    _isLoading = true;
    _error = null;
    notifyListeners();

    try {
      final result = await VaultChannel.listVaults();
      _vaults = result.map((e) => VaultInfo.fromJson(e)).toList();
      _vaults.sort((a, b) => a.createdAt.compareTo(b.createdAt)); // Oldest first (new vaults at bottom)
    } catch (e) {
      _error = e.toString();
      _vaults = [];
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Create a new vault with encrypted title
  Future<bool> createVault({
    required String title,
    required String password,
  }) async {
    if (!canAddVault) {
      _error = 'Maximum $maxVaults vaults reached';
      notifyListeners();
      return false;
    }

    _error = null;
    
    try {
      final result = await VaultChannel.createVaultWithTitle(
        title: title,
        password: password,
      );
      
      if (result != null) {
        final newVault = VaultInfo.fromJson(result);
        _vaults.add(newVault); // Add at bottom (oldest first order)
        notifyListeners();
        return true;
      }
      _error = 'Failed to create vault - no response from native';
      notifyListeners();
      return false;
    } catch (e) {
      // Extract meaningful error message from PlatformException
      String errorMsg = e.toString();
      if (errorMsg.contains('PlatformException')) {
        // Format: PlatformException(CODE, message, details)
        final match = RegExp(r'PlatformException\([^,]+,\s*([^,]+)').firstMatch(errorMsg);
        if (match != null) {
          errorMsg = match.group(1)?.trim() ?? 'Unknown error';
        }
      }
      _error = errorMsg.isEmpty ? 'Failed to create vault' : errorMsg;
      notifyListeners();
      return false;
    }
  }

  /// Import a vault file (title is read from inside the vault)
  /// Uses 2-step flow: pick file first, then import with progress
  Future<bool> importVault() async {
    if (!canAddVault) {
      _error = 'Maximum $maxVaults vaults reached';
      notifyListeners();
      return false;
    }

    try {
      // Step 1: Pick file (quick, no loading needed)
      final uri = await VaultChannel.pickVaultFile();
      if (uri == null) {
        // User cancelled picker
        return false;
      }

      // Step 2: Import from URI (with progress tracking)
      final result = await VaultChannel.importVaultFromUri(uri);
      
      if (result != null) {
        final newVault = VaultInfo.fromJson(result);
        _vaults.add(newVault); // Add at bottom (oldest first order)
        notifyListeners();
        return true;
      }
      return false;
    } catch (e) {
      _error = e.toString();
      notifyListeners();
      return false;
    }
  }

  /// Get decrypted title for a vault (requires password)
  /// Returns empty string for legacy vaults without title
  /// Throws exception on auth failure
  Future<String?> revealTitle(String vaultId, String password) async {
    // This will throw PlatformException if auth fails
    return await VaultChannel.getVaultTitle(vaultId: vaultId, password: password);
  }

  /// Update vault title (requires password)
  Future<bool> updateTitle(String vaultId, String password, String newTitle) async {
    try {
      final success = await VaultChannel.setVaultTitle(
        vaultId: vaultId,
        password: password,
        newTitle: newTitle,
      );
      return success;
    } catch (e) {
      return false;
    }
  }

  /// Delete a vault completely
  Future<bool> deleteVault(String vaultId) async {
    try {
      final success = await VaultChannel.deleteVault(vaultId: vaultId);
      if (success) {
        _vaults.removeWhere((v) => v.id == vaultId);
        notifyListeners();
      }
      return success;
    } catch (e) {
      _error = e.toString();
      notifyListeners();
      return false;
    }
  }

  /// Set current active vault
  void setCurrentVault(String? vaultId) {
    _currentVaultId = vaultId;
    notifyListeners();
  }

  /// Clear error
  void clearError() {
    _error = null;
    notifyListeners();
  }
}
