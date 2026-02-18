package fr.synqkro.api.common.service;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;

/**
 * Service de géolocalisation IP et d'analyse ASN (Autonomous System Number).
 * Utilise la base de données MaxMind GeoLite2 (format MMDB).
 */
@Service
@Slf4j
public class GeoLocationService {

    @Value("classpath:geoip/GeoLite2-City.mmdb")
    private Resource cityDbResource;

    @Value("classpath:geoip/GeoLite2-ASN.mmdb")
    private Resource asnDbResource;

    private DatabaseReader cityReader;
    private DatabaseReader asnReader;

    // Liste simplifiée d'ASN de datacenters/cloud providers majeurs (AWS, Google,
    // Azure, DigitalOcean, OVH...)
    // En production, cette liste pourrait être plus exhaustive ou mise à jour
    // dynamiquement.
    private static final List<Integer> KNOWN_DATACENTER_ASNS = Arrays.asList(
            16509, 14618, 16276, // Amazon
            15169, 396982, // Google
            8075, 8068, // Microsoft
            14061, // DigitalOcean
            16276, // OVH
            24940, // Hetzner
            45102, // Alibaba
            31898 // Oracle
    );

    @PostConstruct
    public void init() {
        try {
            if (cityDbResource.exists()) {
                cityReader = new DatabaseReader.Builder(cityDbResource.getInputStream()).build();
                log.info("GeoLite2-City database loaded successfully.");
            } else {
                log.warn("GeoLite2-City database not found. Geolocation features will be disabled.");
            }

            if (asnDbResource.exists()) {
                asnReader = new DatabaseReader.Builder(asnDbResource.getInputStream()).build();
                log.info("GeoLite2-ASN database loaded successfully.");
            } else {
                log.warn("GeoLite2-ASN database not found. ASN/Datacenter detection features will be limited.");
            }
        } catch (IOException e) {
            log.error("Failed to load GeoIP databases", e);
        }
    }

    @PreDestroy
    public void cleanup() {
        try {
            if (cityReader != null)
                cityReader.close();
            if (asnReader != null)
                asnReader.close();
        } catch (IOException e) {
            log.warn("Error closing GeoIP readers", e);
        }
    }

    /**
     * Récupère le code pays (ISO 3166-1 alpha-2) pour une IP.
     */
    public String getCountryCode(String ip) {
        if (cityReader == null || isLocalIp(ip))
            return null;
        try {
            CityResponse response = cityReader.city(InetAddress.getByName(ip));
            return response.getCountry().getIsoCode();
        } catch (IOException | GeoIp2Exception e) {
            log.debug("Failed to lookup country for IP {}: {}", ip, e.getMessage());
            return null;
        }
    }

    /**
     * Récupère le nom de la ville pour une IP.
     */
    public String getCity(String ip) {
        if (cityReader == null || isLocalIp(ip))
            return null;
        try {
            CityResponse response = cityReader.city(InetAddress.getByName(ip));
            return response.getCity().getName();
        } catch (IOException | GeoIp2Exception e) {
            log.debug("Failed to lookup city for IP {}: {}", ip, e.getMessage());
            return null;
        }
    }

    /**
     * Récupère l'ASN (Autonomous System Number) pour une IP.
     */
    public Integer getAsn(String ip) {
        if (asnReader == null || isLocalIp(ip))
            return null;
        try {
            AsnResponse response = asnReader.asn(InetAddress.getByName(ip));
            return Math.toIntExact(response.getAutonomousSystemNumber());
        } catch (IOException | GeoIp2Exception e) {
            log.debug("Failed to lookup ASN for IP {}: {}", ip, e.getMessage());
            return null;
        }
    }

    /**
     * Vérifie si l'IP appartient à un datacenter connu (basé sur ASN).
     */
    public boolean isDatacenterIp(String ip) {
        Integer asn = getAsn(ip);
        if (asn == null)
            return false;
        return KNOWN_DATACENTER_ASNS.contains(asn);
    }

    private boolean isLocalIp(String ip) {
        return ip == null ||
                ip.equals("127.0.0.1") ||
                ip.equals("0:0:0:0:0:0:0:1") ||
                ip.startsWith("192.168.") ||
                ip.startsWith("10.");
    }
}
