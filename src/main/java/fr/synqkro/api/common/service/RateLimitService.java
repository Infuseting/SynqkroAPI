package fr.synqkro.api.common.service;

import fr.synqkro.api.common.config.RateLimitConfig;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.function.Supplier;

/**
 * Service de rate limiting distribué utilisant Bucket4j + Redis.
 * Permet de limiter les requêtes par IP ou par userId selon la route.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RateLimitService {

    private final ProxyManager<String> buckets;

    /**
     * Tente de consommer un jeton du bucket.
     * 
     * @param key    Clé unique (IP ou userId)
     * @param config Configuration de rate limit
     * @return true si le jeton a été consommé (requête acceptée), false sinon (rate
     *         limited)
     */
    public boolean tryConsume(String key, RateLimitConfig config) {
        String bucketKey = buildKey(config, key);

        Bucket bucket = buckets.builder().build(bucketKey, () -> createBucketConfiguration(config));

        boolean consumed = bucket.tryConsume(1);

        if (!consumed) {
            log.warn("Rate limit exceeded for key: {} (config: {})", key, config.name());
        }

        return consumed;
    }

    /**
     * Récupère le nombre de tokens restants.
     */
    public long getRemainingTokens(String key, RateLimitConfig config) {
        String bucketKey = buildKey(config, key);

        Bucket bucket = buckets.builder().build(bucketKey, () -> createBucketConfiguration(config));

        return bucket.getAvailableTokens();
    }

    /**
     * Récupère le temps en secondes avant le prochain refill.
     */
    public long getSecondsToRefill(String key, RateLimitConfig config) {
        String bucketKey = buildKey(config, key);

        Bucket bucket = buckets.builder().build(bucketKey, () -> createBucketConfiguration(config));

        return bucket.estimateAbilityToConsume(1).getNanosToWaitForRefill() / 1_000_000_000;
    }

    /**
     * Reset manuel d'un bucket (admin only).
     */
    public void resetBucket(String key, RateLimitConfig config) {
        String bucketKey = buildKey(config, key);
        buckets.removeProxy(bucketKey);
        log.info("Bucket reset for key: {} (config: {})", key, config.name());
    }

    /**
     * Construit la clé Redis complète pour le bucket.
     */
    private String buildKey(RateLimitConfig config, String identifier) {
        return "ratelimit:" + config.name().toLowerCase() + ":" + identifier;
    }

    /**
     * Crée la configuration Bucket4j à partir de RateLimitConfig.
     */
    private BucketConfiguration createBucketConfiguration(RateLimitConfig config) {
        Bandwidth limit = Bandwidth.builder()
                .capacity(config.getCapacity())
                .refillGreedy(config.getCapacity(), config.getWindow())
                .build();

        return BucketConfiguration.builder()
                .addLimit(limit)
                .build();
    }

    /**
     * Vérifie si la clé est rate limited sans consommer de jeton.
     */
    public boolean isRateLimited(String key, RateLimitConfig config) {
        return getRemainingTokens(key, config) == 0;
    }

    /**
     * Helper pour rate limiting par IP.
     */
    public boolean tryConsumeByIp(String ip, RateLimitConfig config) {
        return tryConsume(ip, config);
    }

    /**
     * Helper pour rate limiting par userId.
     */
    public boolean tryConsumeByUserId(Long userId, RateLimitConfig config) {
        return tryConsume(String.valueOf(userId), config);
    }
}
