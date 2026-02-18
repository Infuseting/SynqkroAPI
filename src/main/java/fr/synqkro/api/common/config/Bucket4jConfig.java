package fr.synqkro.api.common.config;

import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.codec.RedisCodec;
import io.lettuce.core.codec.StringCodec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

/**
 * Configuration Redis et Bucket4j.
 *
 * <p>
 * Crée un {@link RedisClient} Lettuce unique partagé entre :
 * <ul>
 * <li>{@link RedisConnectionFactory} — utilisé par {@link RedisConfig} pour
 * {@code RedisTemplate}</li>
 * <li>{@link StatefulRedisConnection} — utilisé par Bucket4j pour le rate
 * limiting distribué</li>
 * </ul>
 */
@Configuration
public class Bucket4jConfig {

    @Value("${spring.data.redis.host:localhost}")
    private String redisHost;

    @Value("${spring.data.redis.port:6379}")
    private int redisPort;

    @Value("${spring.data.redis.password:}")
    private String redisPassword;

    /**
     * Client Redis Lettuce partagé.
     */
    @Bean(destroyMethod = "shutdown")
    public RedisClient redisClient() {
        RedisURI.Builder uriBuilder = RedisURI.builder()
                .withHost(redisHost)
                .withPort(redisPort);

        if (redisPassword != null && !redisPassword.isEmpty()) {
            uriBuilder.withPassword(redisPassword.toCharArray());
        }

        return RedisClient.create(uriBuilder.build());
    }

    /**
     * RedisConnectionFactory basé sur Lettuce — requis par RedisTemplate (Spring
     * Data Redis).
     */
    @Bean
    public RedisConnectionFactory redisConnectionFactory(RedisClient redisClient) {
        LettuceConnectionFactory factory = new LettuceConnectionFactory(redisHost, redisPort);
        factory.afterPropertiesSet();
        return factory;
    }

    /**
     * Connexion Redis pour Bucket4j (clé String, valeur byte[]).
     */
    @Bean
    public StatefulRedisConnection<String, byte[]> redisConnection(RedisClient redisClient) {
        return redisClient.connect(RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE));
    }

    /**
     * ProxyManager Bucket4j — gère les buckets distribués dans Redis.
     */
    @Bean
    public ProxyManager<String> buckets(StatefulRedisConnection<String, byte[]> redisConnection) {
        return LettuceBasedProxyManager.builderFor(redisConnection).build();
    }
}
