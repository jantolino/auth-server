package edu.market.authserver.infrastructure.config.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * Configuración de JWKS (JSON Web Key Set) para el servidor de autorización OAuth2. Esta clase
 * contiene los beans necesarios para la gestión de claves y la decodificación de JWT.
 */
@Slf4j
@Configuration
public class JwkConfig {

  /**
   * Configura el origen de las claves JWK. Carga las claves RSA desde un keystore para firmar y
   * verificar tokens JWT.
   *
   * @return Origen de claves JWK
   * @throws Exception Si ocurre un error al cargar las claves
   */
  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey =
        new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }

  private static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  /**
   * @apiNote Ejemplo de Configura el JWKSource para exponer la clave pública: utilizando las claves
   *     colocadas en la carpeta reources/keys/
   */
  private JWKSource<SecurityContext> jwkSourceExample() throws Exception {

    // Cargar la clave publica y privada desde el archivo
    InputStream privateKeykinputStream = new ClassPathResource("keys/private.pem").getInputStream();
    InputStream publicKeyInputStream = new ClassPathResource("keys/public.pem").getInputStream();

    String privateKeyPem =
        new String(privateKeykinputStream.readAllBytes())
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");

    byte[] keyBytes = Base64.getDecoder().decode(privateKeyPem);
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPrivateKey privateKey = (RSAPrivateKey) kf.generatePrivate(keySpec);

    String publicKeyPem =
        new String(publicKeyInputStream.readAllBytes())
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");

    byte[] pubKeyBytes = Base64.getDecoder().decode(publicKeyPem);
    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
    RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(pubKeySpec);

    RSAKey rsaKey =
        new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();

    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  /**
   * Configura el personalizador de tokens JWT. Añade claims personalizados al token JWT basados en
   * la información del usuario y sus roles. Combina la funcionalidad de añadir roles y la
   * información detallada del usuario.
   *
   * @return Personalizador de tokens JWT
   */
  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
    return (context) -> {

      RegisteredClient registeredClient = context.getRegisteredClient();
      Set<String> scopes = registeredClient.getScopes();
      // Sobrescribe una propiedad
      context.getClaims().claim("scope", scopes);

      // Crea una propiedad
      context.getClaims().claim("grant_type", registeredClient.getAuthorizationGrantTypes());
    };
  }
  
}
