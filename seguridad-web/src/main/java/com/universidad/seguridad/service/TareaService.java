package com.universidad.seguridad.service;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.repository.TareaRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TareaService {

    private final TareaRepository tareaRepository;

    public TareaService(TareaRepository tareaRepository) {
        this.tareaRepository = tareaRepository;
    }

    public List<Tarea> listarDe(Long usuarioId) {
        return tareaRepository.findByPropietarioId(usuarioId);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public List<Tarea> listarTodas() {
        return tareaRepository.findAll();
    }

    public Tarea crear(Tarea tarea) {
        return tareaRepository.save(tarea);
    }

    public List<Tarea> buscar(String texto) {
        if (texto == null || texto.trim().isEmpty()) {
            return tareaRepository.findAll();
        }
        return tareaRepository.buscarPorTitulo(texto);
    }
}

