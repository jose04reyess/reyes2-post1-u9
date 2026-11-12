package com.universidad.seguridad.controller;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.service.TareaService;
import com.universidad.seguridad.service.UsuarioService;
import jakarta.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.List;

@Controller
public class AuthController {

    private final UsuarioService usuarioService;
    private final TareaService tareaService;

    public AuthController(UsuarioService usuarioService, TareaService tareaService) {
        this.usuarioService = usuarioService;
        this.tareaService = tareaService;
    }

    @GetMapping("/")
    public String index() {
        return "redirect:/dashboard";
    }

    @GetMapping("/login")
    public String login() {
        return "auth/login";
    }

    @GetMapping("/registro")
    public String registro(Model model) {
        if (!model.containsAttribute("usuario")) {
            model.addAttribute("usuario", new Usuario());
        }
        return "auth/registro";
    }

    @PostMapping("/registro")
    public String registrarUsuario(
            @Valid @ModelAttribute("usuario") Usuario usuario,
            BindingResult bindingResult,
            Model model) {

        if (bindingResult.hasErrors()) {
            return "auth/registro";
        }

        try {
            usuarioService.registrar(usuario);
        } catch (IllegalArgumentException e) {
            model.addAttribute("errorRegistro", e.getMessage());
            return "auth/registro";
        }

        return "redirect:/login?registrado";
    }

    @GetMapping("/dashboard")
    public String dashboard(Principal principal, Model model) {
        if (principal == null) {
            return "redirect:/login";
        }

        Usuario usuario = usuarioService.buscarPorEmail(principal.getName());
        model.addAttribute("usuario", usuario);
        model.addAttribute("nombreUsuario", usuario.getNombre());
        model.addAttribute("tareas", tareaService.listarDe(usuario.getId()));
        if (!model.containsAttribute("nuevaTarea")) {
            model.addAttribute("nuevaTarea", new Tarea());
        }
        return "dashboard";
    }

    @PostMapping("/tareas")
    public String crearTarea(
            Principal principal,
            @Valid @ModelAttribute("nuevaTarea") Tarea nuevaTarea,
            BindingResult bindingResult,
            Model model) {

        if (principal == null) {
            return "redirect:/login";
        }

        Usuario usuario = usuarioService.buscarPorEmail(principal.getName());

        if (bindingResult.hasErrors()) {
            model.addAttribute("usuario", usuario);
            model.addAttribute("nombreUsuario", usuario.getNombre());
            model.addAttribute("tareas", tareaService.listarDe(usuario.getId()));
            return "dashboard";
        }

        nuevaTarea.setPropietario(usuario);
        tareaService.crear(nuevaTarea);
        return "redirect:/dashboard";
    }

    @GetMapping("/tareas/buscar")
    public String buscarTareas(
            @RequestParam(name = "texto", required = false, defaultValue = "") String texto,
            Principal principal,
            Model model) {

        if (principal == null) {
            return "redirect:/login";
        }

        Usuario usuario = usuarioService.buscarPorEmail(principal.getName());
        List<Tarea> tareasCoincidentes = tareaService.buscar(texto);

        // Si no es admin, filtra para mostrar únicamente las tareas pertenecientes al usuario actual
        if (!"ROLE_ADMIN".equals(usuario.getRol())) {
            tareasCoincidentes = tareasCoincidentes.stream()
                    .filter(t -> t.getPropietario() != null && t.getPropietario().getId().equals(usuario.getId()))
                    .toList();
        }

        model.addAttribute("usuario", usuario);
        model.addAttribute("nombreUsuario", usuario.getNombre());
        model.addAttribute("tareas", tareasCoincidentes);
        model.addAttribute("nuevaTarea", new Tarea());
        model.addAttribute("textoBusqueda", texto);
        return "dashboard";
    }

    @GetMapping("/admin")
    public String adminPanel(Model model) {
        model.addAttribute("usuarios", usuarioService.listarTodos());
        return "admin/panel";
    }
}

