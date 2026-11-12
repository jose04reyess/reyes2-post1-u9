package com.universidad.seguridad.config;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.TareaRepository;
import com.universidad.seguridad.repository.UsuarioRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UsuarioRepository usuarioRepository;
    private final TareaRepository tareaRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(
            UsuarioRepository usuarioRepository,
            TareaRepository tareaRepository,
            PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.tareaRepository = tareaRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        final String adminEmail = "admin@universidad.edu";

        if (!usuarioRepository.existsByEmail(adminEmail)) {
            Usuario admin = new Usuario();
            admin.setNombre("Administrador");
            admin.setEmail(adminEmail);
            admin.setContrasenia(passwordEncoder.encode("admin123"));
            admin.setRol("ROLE_ADMIN");
            admin.setActivo(true);

            admin = usuarioRepository.save(admin);

            Tarea tareaInicial = new Tarea();
            tareaInicial.setTitulo("Auditoría de Seguridad Inicial OWASP");
            tareaInicial.setDescripcion("Revisar controles de autenticación, CSRF, mitigación de XSS y parametrización SQL.");
            tareaInicial.setPropietario(admin);
            tareaInicial.setCompletada(false);

            tareaRepository.save(tareaInicial);
        }
    }
}

