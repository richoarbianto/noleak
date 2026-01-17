/// Metadata for a vault in the multi-vault registry.
/// 
/// This class stores non-sensitive metadata about a vault that can be
/// displayed without unlocking the vault. The actual vault title is
/// stored encrypted inside the vault file and requires authentication
/// to reveal.
/// 
/// Properties:
/// - [id]: Unique identifier (UUID) for the vault
/// - [filename]: Name of the vault file on disk
/// - [createdAt]: Timestamp when the vault was created
/// - [sizeBytes]: Total size of the vault file
class VaultInfo {
  final String id;
  final String filename;
  final DateTime createdAt;
  final int sizeBytes;

  const VaultInfo({
    required this.id,
    required this.filename,
    required this.createdAt,
    this.sizeBytes = 0,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'filename': filename,
    'createdAt': createdAt.millisecondsSinceEpoch,
    'sizeBytes': sizeBytes,
  };

  factory VaultInfo.fromJson(Map<String, dynamic> json) => VaultInfo(
    id: json['id'] as String,
    filename: json['filename'] as String,
    createdAt: DateTime.fromMillisecondsSinceEpoch(json['createdAt'] as int),
    sizeBytes: (json['sizeBytes'] as int?) ?? 0,
  );

  VaultInfo copyWith({
    String? id,
    String? filename,
    DateTime? createdAt,
    int? sizeBytes,
  }) => VaultInfo(
    id: id ?? this.id,
    filename: filename ?? this.filename,
    createdAt: createdAt ?? this.createdAt,
    sizeBytes: sizeBytes ?? this.sizeBytes,
  );
}
