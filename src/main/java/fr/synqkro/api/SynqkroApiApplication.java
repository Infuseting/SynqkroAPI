package fr.synqkro.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import me.paulschwarz.springdotenv.DotenvPropertySource;
import org.springframework.core.env.ConfigurableEnvironment;

@SpringBootApplication
public class SynqkroApiApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(SynqkroApiApplication.class);
        app.addInitializers(ctx -> {
            ConfigurableEnvironment env = ctx.getEnvironment();
            DotenvPropertySource.addToEnvironment(env);
        });
        app.run(args);
    }

}
