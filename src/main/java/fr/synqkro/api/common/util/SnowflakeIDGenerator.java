package fr.synqkro.api.common.util;


import fr.synqkro.api.common.exception.ClockBackwardsException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@Slf4j
public class SnowflakeIDGenerator {

    private static final long CUSTOM_EPOCH = 1704067200000L;

    private static final int TIMESTAMP_BITS  = 41;
    private static final int MACHINE_ID_BITS = 10;
    private static final int SEQUENCE_BITS   = 12;

    private static final long MAX_MACHINE_ID = ~(-1L << MACHINE_ID_BITS);
    private static final long MAX_SEQUENCE   = ~(-1L << SEQUENCE_BITS);

    private static final int MACHINE_ID_SHIFT  = SEQUENCE_BITS;
    private static final int TIMESTAMP_SHIFT   = SEQUENCE_BITS + MACHINE_ID_BITS;

    private final long machineId;
    private long lastTimestamp = -1L;
    private long sequence      = 0L;

    private final Object lock = new Object();


    public SnowflakeIDGenerator(@Value("${snowflake.machine-id}") long machineId) {
        if (machineId < 0 || machineId > MAX_MACHINE_ID) {
            throw new IllegalArgumentException(
                    "machineId must be between 0 and " + MAX_MACHINE_ID + ", got: " + machineId
            );
        }
        this.machineId = machineId;
        log.info("SnowflakeIdGenerator initialized — machineId={}", machineId);
    }

    public long nextId() {
        synchronized (lock) {
            long now = currentMs();

            if (now < lastTimestamp) {
                long drift = lastTimestamp - now;

                if (drift <= 5) {
                    log.warn("Clock moved backwards {}ms — waiting", drift);
                    now = waitUntil(lastTimestamp);
                } else {
                    throw new ClockBackwardsException(
                            "Clock moved backwards by " + drift + "ms — cannot generate ID safely"
                    );
                }
            }

            if (now == lastTimestamp) {
                sequence = (sequence + 1) & MAX_SEQUENCE;

                if (sequence == 0) {
                    now = waitUntil(lastTimestamp);
                }
            } else {
                sequence = 0L;
            }

            lastTimestamp = now;

            return ((now - CUSTOM_EPOCH) << TIMESTAMP_SHIFT)
                    | (machineId            << MACHINE_ID_SHIFT)
                    |  sequence;
        }
    }


    public SnowflakeComponents decompose(long id) {
        long timestamp = (id >> TIMESTAMP_SHIFT) + CUSTOM_EPOCH;
        long machine   = (id >> MACHINE_ID_SHIFT) & MAX_MACHINE_ID;
        long seq       = id & MAX_SEQUENCE;

        return new SnowflakeComponents(id, Instant.ofEpochMilli(timestamp), machine, seq);
    }

    private long currentMs() {
        return System.currentTimeMillis();
    }

    private long waitUntil(long targetMs) {
        long now = currentMs();
        while (now <= targetMs) {
            Thread.onSpinWait();
            now = currentMs();
        }
        return now;
    }

    public record SnowflakeComponents(
            long    id,
            Instant createdAt,
            long    machineId,
            long    sequence
    ) {}
}