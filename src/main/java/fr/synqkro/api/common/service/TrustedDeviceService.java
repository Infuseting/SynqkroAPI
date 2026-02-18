package fr.synqkro.api.common.service;

import fr.synqkro.api.common.entity.TrustedDeviceEntity;
import fr.synqkro.api.common.repository.TrustedDeviceRepository;
import fr.synqkro.api.common.util.SnowflakeIDGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Service pour la gestion des appareils de confiance (Trusted Devices).
 * Inspiré du système "Appareils connectés" de Google et Apple.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TrustedDeviceService {

    private final TrustedDeviceRepository trustedDeviceRepository;
    private final SnowflakeIDGenerator snowflake;

    /**
     * Trouve ou crée un appareil pour un utilisateur et un fingerprint.
     */
    @Transactional
    public TrustedDeviceEntity findOrCreate(Long userId, String fingerprint) {
        Optional<TrustedDeviceEntity> existing = trustedDeviceRepository.findByUserIdAndFingerprint(userId,
                fingerprint);

        if (existing.isPresent()) {
            TrustedDeviceEntity device = existing.get();
            if (!device.isExpired()) {
                return device;
            }
            // Si expiré, on le supprime et en crée un nouveau
            trustedDeviceRepository.delete(device);
        }

        // Créer nouveau device (non trusted par défaut)
        TrustedDeviceEntity newDevice = TrustedDeviceEntity.builder()
                .id(snowflake.nextId())
                .userId(userId)
                .fingerprint(fingerprint)
                .trusted(false)
                .build();

        return trustedDeviceRepository.save(newDevice);
    }

    /**
     * Marque un appareil comme "de confiance" avec un nom personnalisé.
     */
    @Transactional
    public void trustDevice(Long userId, Long deviceId, String name) {
        TrustedDeviceEntity device = trustedDeviceRepository.findById(deviceId)
                .orElseThrow(() -> new IllegalArgumentException("Device not found: " + deviceId));

        if (!device.getUserId().equals(userId)) {
            throw new SecurityException("Device does not belong to user");
        }

        device.setTrusted(true);
        device.setName(name);
        device.renewExpiration();
        trustedDeviceRepository.save(device);

        log.info("Device {} trusted by user {}: {}", deviceId, userId, name);
    }

    /**
     * Révoque (supprime) un appareil de confiance.
     */
    @Transactional
    public void revokeDevice(Long userId, Long deviceId) {
        TrustedDeviceEntity device = trustedDeviceRepository.findById(deviceId)
                .orElseThrow(() -> new IllegalArgumentException("Device not found: " + deviceId));

        if (!device.getUserId().equals(userId)) {
            throw new SecurityException("Device does not belong to user");
        }

        trustedDeviceRepository.delete(device);
        log.info("Device {} revoked by user {}", deviceId, userId);
    }

    /**
     * Liste tous les appareils d'un utilisateur.
     */
    public List<TrustedDeviceEntity> listDevices(Long userId) {
        return trustedDeviceRepository.findAllByUserId(userId);
    }

    /**
     * Liste uniquement les appareils de confiance.
     */
    public List<TrustedDeviceEntity> listTrustedDevices(Long userId) {
        return trustedDeviceRepository.findByUserIdAndTrustedTrue(userId);
    }

    /**
     * Vérifie si un fingerprint correspond à un appareil de confiance valide.
     */
    public boolean isTrusted(Long userId, String fingerprint) {
        return trustedDeviceRepository.isTrustedDevice(userId, fingerprint, Instant.now());
    }

    /**
     * Renouvelle l'expiration d'un appareil (appelé à chaque usage).
     */
    @Transactional
    public void renewExpiration(Long deviceId) {
        trustedDeviceRepository.findById(deviceId).ifPresent(device -> {
            device.renewExpiration();
            trustedDeviceRepository.save(device);
        });
    }

    /**
     * Met à jour les informations de dernière utilisation d'un device.
     */
    @Transactional
    public void updateLastSeen(Long deviceId, String ip, String userAgent, String countryCode) {
        trustedDeviceRepository.findById(deviceId).ifPresent(device -> {
            device.updateLastSeen(ip, userAgent, countryCode);
            trustedDeviceRepository.save(device);
        });
    }

    /**
     * Tâche scheduled pour nettoyer les appareils expirés (tous les jours à 3h).
     */
    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void cleanupExpired() {
        int deleted = trustedDeviceRepository.deleteExpired(Instant.now());
        if (deleted > 0) {
            log.info("Cleaned up {} expired trusted devices", deleted);
        }
    }

    /**
     * Révoque tous les appareils d'un utilisateur (par exemple lors de la
     * suppression du compte).
     */
    @Transactional
    public void revokeAllDevices(Long userId) {
        trustedDeviceRepository.deleteByUserId(userId);
        log.info("All devices revoked for user {}", userId);
    }

    /**
     * Compte le nombre d'appareils de confiance actifs.
     */
    public long countTrustedDevices(Long userId) {
        return trustedDeviceRepository.countByUserIdAndTrustedTrue(userId);
    }
}
