import Foundation

// Validator para entrada estricta de BitchatPacket
// Integración esperada: llamar PacketValidator.validateInboundPacket(...) lo antes posible
// en la tubería de recepción (p.ej. en BLEService.handleReceivedPacket) y rechazar/registrar en caso de error.

public enum PacketValidationError: Error, Equatable {
    case missingSignature
    case invalidSignatureLength
    case missingSigningPublicKey
    case invalidSignature
    case invalidSignatureOwnership
    case malformedTimestamp
    case packetExpired
}

public struct PacketValidator {
    // Reproducir la ventana de replay solicitada: 5 minutos (en milisegundos)
    public static let replayWindow: TimeInterval = 5 * 60 // seconds

    /// Valida estrictamente el paquete y devuelve una copia segura del payload si TODO es correcto.
    ///
    /// Dependencias inyectadas:
    /// - now: fuente de tiempo (útil para tests)
    /// - resolveNoisePublicKey: devuelve la Noise static public key (32 bytes) asociada al PeerID remitente, si se conoce
    /// - resolveSigningPublicKeyForFingerprint: devuelve la Ed25519 signing public key (32 bytes) para un fingerprint SHA256 dado, si se conoce
    /// - verifyPacketSignature: función que comprueba la firma (usa el canonical bytes de packet.toBinaryDataForSigning() internamente)
    ///
    /// Fail-fast: si alguna comprobación falla se lanza un error y NUNCA se toca o devuelve payload.
    public static func validateInboundPacket(
        _ pkt: BitchatPacket,
        claimedSenderID: PeerID,
        now: () -> Date = { Date() },
        resolveNoisePublicKey: (PeerID) -> Data?,
        resolveSigningPublicKeyForFingerprint: (String) -> Data?,
        verifyPacketSignature: (BitchatPacket, Data) -> Bool
    ) throws -> Data {
        // 1) Firma obligatoria
        guard let sig = pkt.signature else {
            throw PacketValidationError.missingSignature
        }
        if sig.count != 64 {
            throw PacketValidationError.invalidSignatureLength
        }

        // 2) Timestamp anti-replay: packet.timestamp es UInt64 en milisegundos
        let tsMs = pkt.timestamp
        guard tsMs != 0 else { throw PacketValidationError.malformedTimestamp }
        let packetDate = Date(timeIntervalSince1970: TimeInterval(tsMs) / 1000.0)
        let delta = abs(now().timeIntervalSince(packetDate))
        if delta > PacketValidator.replayWindow {
            throw PacketValidationError.packetExpired
        }

        // 3) Identity binding + criptográfica
        // Manejo especial: announce packets llevan la pareja (noisePublicKey + signingPublicKey) en el payload.
        // - Para announce: decode AnnouncementPacket y comprobar derivedPeerID == claimedSenderID,
        //   y usar announcement.signingPublicKey para verificar firma.
        // - Para otros tipos: resolvemos la noisePublicKey conocida para el claimedSenderID (peerRegistry/identity store),
        //   derivamos fingerprint -> buscamos signingPublicKey vinculada. Luego:
        //     a) comprobar que PeerID(publicKey: noisePublicKey) == claimedSenderID
        //     b) verificar firma con la signingPublicKey encontrada
        //
        // Nota: NO procesamos ni analizamos el payload hasta pasadas estas comprobaciones.

        // Try announce path first (AnnouncementPacket.decode may be project type; guard optional)
        if pkt.type == MessageType.announce.rawValue {
            // Intentamos decodificar AnnouncementPacket desde payload de forma no-destructiva
            guard let announcement = AnnouncementPacket.decode(from: pkt.payload) else {
                // Si no podemos decodificar, no asumimos signingPublicKey; fallamos por ownership faltante
                throw PacketValidationError.missingSigningPublicKey
            }

            // Derivar PeerID desde noisePublicKey del announcement y comparar con claimedSenderID
            let derived = PeerID(publicKey: announcement.noisePublicKey)
            if derived != claimedSenderID {
                throw PacketValidationError.invalidSignatureOwnership
            }

            // Debe existir signingPublicKey en el anuncio
            guard let signingKey = announcement.signingPublicKey else {
                throw PacketValidationError.missingSigningPublicKey
            }

            // Verificar firma criptográficamente usando la canonicalización existente
            let ok = verifyPacketSignature(pkt, signingKey)
            if !ok {
                throw PacketValidationError.invalidSignature
            }

            // Todas las comprobaciones OK: devolver payload seguro (copia)
            return Data(pkt.payload)
        }

        // Path general: buscar noise public key y signing public key desde stores
        guard let noisePub = resolveNoisePublicKey(claimedSenderID) else {
            // No conocemos la noise key para ese PeerID, no podemos vincular; fail-fast
            throw PacketValidationError.missingSigningPublicKey
        }

        // Verificar que la peer id derivada desde noisePub coincide exactamente con el claimedSenderID
        let derivedPeerID = PeerID(publicKey: noisePub)
        if derivedPeerID != claimedSenderID {
            throw PacketValidationError.invalidSignatureOwnership
        }

        // Buscar la signing key asociada a esa fingerprint (Identity store)
        let fingerprint = noisePub.sha256Fingerprint()
        guard let signingKey = resolveSigningPublicKeyForFingerprint(fingerprint) else {
            // No tenemos la clave de firma asociada a la identidad conocida -> fail-fast
            throw PacketValidationError.missingSigningPublicKey
        }

        // Verificar firma criptográficamente
        let signatureOk = verifyPacketSignature(pkt, signingKey)
        if !signatureOk {
            throw PacketValidationError.invalidSignature
        }

        // Éxito: devolver payload (copia para evitar aliasing)
        return Data(pkt.payload)
    }
}
