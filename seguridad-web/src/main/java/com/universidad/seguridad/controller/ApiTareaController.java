package com.universidad.seguridad.controller;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.service.TareaService;
import com.universidad.seguridad.service.UsuarioService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/tareas")
public class ApiTareaController {

    private final TareaService tareaService;
    private final UsuarioService usuarioService;

    public ApiTareaController(TareaService tareaService, UsuarioService usuarioService) {
        this.tareaService = tareaService;
        this.usuarioService = usuarioService;
    }

    @GetMapping
    public ResponseEntity<List<Tarea>> listar(Authentication auth) {
        Usuario usuario = usuarioService.buscarPorEmail(auth.getName());
        List<Tarea> tareas = tareaService.listarDe(usuario.getId());
        return ResponseEntity.ok(tareas);
    }

    @PostMapping
    public ResponseEntity<Tarea> crear(Authentication auth, @Valid @RequestBody Tarea tarea) {
        Usuario usuario = usuarioService.buscarPorEmail(auth.getName());
        tarea.setPropietario(usuario);
        Tarea guardada = tareaService.crear(tarea);
        return ResponseEntity.ok(guardada);
    }
}

