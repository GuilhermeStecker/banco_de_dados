
-- =====================================================
-- SEGURANCA BASICA - SISTEMA ACADEMICO
-- =====================================================

-- FUNCAO: identificar usuario autenticado
CREATE OR REPLACE FUNCTION public.current_usuario_id()
RETURNS INT
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT id_usuario
    FROM public.usuario
    WHERE auth_user_id = auth.uid()
      AND ativo = TRUE
    LIMIT 1;
$$;

-- FUNCAO: identificar coordenador
CREATE OR REPLACE FUNCTION public.is_coordenador()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.usuario u
        JOIN public.cargo c ON c.id_cargo = u.id_cargo
        WHERE u.auth_user_id = auth.uid()
          AND u.ativo = TRUE
          AND c.nome_cargo = 'Coordenador'
    );
$$;

GRANT EXECUTE ON FUNCTION public.current_usuario_id() TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_coordenador() TO authenticated;

-- ATIVAR RLS NAS TABELAS
ALTER TABLE public.cargo ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.periodo ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.curso ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.disciplina ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.usuario ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.turma ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.coordenador ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aluno ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.professor ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.auditoria ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.disciplina_turma ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.matricula ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.comentario ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.avaliacao ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aula ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.aluno_avaliacao ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.frequencia ENABLE ROW LEVEL SECURITY;

-- LEITURA DE INFORMACOES GERAIS
CREATE POLICY cargo_leitura ON public.cargo
FOR SELECT TO authenticated USING (true);

CREATE POLICY periodo_leitura ON public.periodo
FOR SELECT TO authenticated USING (true);

CREATE POLICY curso_leitura ON public.curso
FOR SELECT TO authenticated USING (true);

CREATE POLICY disciplina_leitura ON public.disciplina
FOR SELECT TO authenticated USING (true);

-- USUARIO: somente o proprio registro ou coordenador
CREATE POLICY usuario_leitura ON public.usuario
FOR SELECT TO authenticated
USING (
    auth_user_id = auth.uid()
    OR public.is_coordenador()
);

CREATE POLICY usuario_coordenador ON public.usuario
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

-- COORDENADOR: acesso completo as tabelas
CREATE POLICY coordenador_cargo ON public.cargo
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_periodo ON public.periodo
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_curso ON public.curso
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_disciplina ON public.disciplina
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_turma ON public.turma
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador ON public.coordenador
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_aluno ON public.aluno
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_professor ON public.professor
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_auditoria ON public.auditoria
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_disciplina_turma ON public.disciplina_turma
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_matricula ON public.matricula
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_comentario ON public.comentario
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_avaliacao ON public.avaliacao
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_aula ON public.aula
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_aluno_avaliacao ON public.aluno_avaliacao
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

CREATE POLICY coordenador_frequencia ON public.frequencia
FOR ALL TO authenticated
USING (public.is_coordenador())
WITH CHECK (public.is_coordenador());

-- PERFIS: consulta do proprio cadastro
CREATE POLICY aluno_proprio ON public.aluno
FOR SELECT TO authenticated
USING (
    id_usuario = public.current_usuario_id()
);

CREATE POLICY professor_proprio ON public.professor
FOR SELECT TO authenticated
USING (
    id_usuario = public.current_usuario_id()
);

CREATE POLICY coordenador_proprio ON public.coordenador
FOR SELECT TO authenticated
USING (
    id_usuario = public.current_usuario_id()
);

-- DADOS ACADEMICOS: leitura autenticada
CREATE POLICY turma_leitura ON public.turma
FOR SELECT TO authenticated USING (true);

CREATE POLICY matricula_leitura ON public.matricula
FOR SELECT TO authenticated USING (true);

CREATE POLICY disciplina_turma_leitura ON public.disciplina_turma
FOR SELECT TO authenticated USING (true);

CREATE POLICY aula_leitura ON public.aula
FOR SELECT TO authenticated USING (true);

CREATE POLICY avaliacao_leitura ON public.avaliacao
FOR SELECT TO authenticated USING (true);

CREATE POLICY nota_leitura ON public.aluno_avaliacao
FOR SELECT TO authenticated USING (true);

CREATE POLICY frequencia_leitura ON public.frequencia
FOR SELECT TO authenticated USING (true);

CREATE POLICY comentario_leitura ON public.comentario
FOR SELECT TO authenticated USING (true);

-- =====================================================
-- FIM DA SEGURANCA BASICA
-- =====================================================