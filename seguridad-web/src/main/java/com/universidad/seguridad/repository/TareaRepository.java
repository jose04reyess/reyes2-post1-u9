package com.universidad.seguridad.repository;

import com.universidad.seguridad.model.Tarea;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TareaRepository extends JpaRepository<Tarea, Long> {

    List<Tarea> findByPropietarioId(Long usuarioId);

    /*
     * PREVENCIÓN DE SQL INJECTION (OWASP Top 10 - A03:2021-Injection):
     *
     * 1. Consulta Segura (Parametrizada con JPQL y @Param):
     *    La siguiente consulta utiliza un placeholder parametrizado (:texto) administrado por Hibernate/JPA.
     *    El motor JDBC genera una sentencia preparada (PreparedStatement), tratando el valor inyectado
     *    estrictamente como un literal de datos (cadena) y no como código SQL ejecutable.
     *
     * 2. Contraste con Consulta Insegura (Concatenación Dinámica Vulnerable):
     *    Si se implementara concatenando strings directamente, por ejemplo:
     *    "SELECT t FROM Tarea t WHERE t.titulo LIKE '%" + texto + "%'"
     *    un atacante podría ingresar como texto:
     *    ' OR '1'='1' --
     *    resultando en:
     *    SELECT * FROM tareas WHERE titulo LIKE '%' OR '1'='1' --%'
     *    lo cual evaluaría '1'='1' como VERDADERO para todas las filas, eludiendo cualquier control
     *    de aislamiento y filtrando información confidencial de todos los usuarios de la base de datos.
     */
    @Query("SELECT t FROM Tarea t WHERE t.titulo LIKE %:texto%")
    List<Tarea> buscarPorTitulo(@Param("texto") String texto);
}

