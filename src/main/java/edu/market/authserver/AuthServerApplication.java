package edu.market.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Clase principal de la aplicación del servidor de autorización OAuth2.
 * Habilita la validación de propiedades de configuración para garantizar
 * que todas las propiedades requeridas estén presentes al iniciar la aplicación.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class AuthServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }
}
