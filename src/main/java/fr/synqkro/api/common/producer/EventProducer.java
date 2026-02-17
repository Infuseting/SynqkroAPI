package fr.synqkro.api.common.producer;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class EventProducer {

    private final KafkaTemplate<String, Object> kafkaTemplate;

    public void publish(String topic, Object payload) {
        kafkaTemplate.send(topic, payload)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.error("Failed to publish event — topic={} error={}", topic, ex.getMessage());
                    } else {
                        log.debug("Event published — topic={} offset={}",
                                topic, result.getRecordMetadata().offset());
                    }
                });
    }
}