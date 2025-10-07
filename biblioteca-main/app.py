from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session , make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
import re 
import pdfkit
from collections import defaultdict


engine = create_engine("sqlite:///music.db")  # 🔹 Ajuste para sua URL de banco

app = Flask(__name__, instance_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance'))
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(basedir, 'instance', 'music.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = os.urandom(24)  # 🔒 Chave única para sessões

db = SQLAlchemy(app)  # 🔹 Mantemos apenas uma inicialização
bcrypt = Bcrypt(app)

login_manager = LoginManager()  # 🔹 Inicializando corretamente
login_manager.init_app(app)  # 🔹 Conectando ao Flask
login_manager.login_view = "login"  # 🔹 Configurando a página de login

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Usuario, int(user_id))  # 🔹 Usa a sessão corretamente sem `with`
    
# 🔹 Definição dos modelos
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), nullable=False)
    sobrenome = db.Column(db.String(50), nullable=False)
    telefone = db.Column(db.String(15), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="membro")
    
    pergunta_seguranca = db.Column(db.String(200), nullable=False)
    resposta_seguranca = db.Column(db.String(200), nullable=False)



class Music(db.Model):
    musica_id = db.Column(db.Integer, primary_key=True)  # 🔹 Agora chamamos a coluna corretamente!
    titulo = db.Column(db.String(100), nullable=False)
    autor = db.Column(db.String(100), nullable=False)
    genero = db.Column(db.String(50), nullable=False)
    tom = db.Column(db.String(10), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    ensaiada = db.Column(db.Boolean, default=False)
    data_ensaio = db.Column(db.DateTime) 

    

class Escala(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    componente = db.Column(db.String(100), nullable=False)
    dia = db.Column(db.String(50), nullable=False)
    horario = db.Column(db.String(50), nullable=False)
    

class Comentario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    musica_id = db.Column(db.Integer, db.ForeignKey('music.musica_id'), nullable=False)
    autor_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    conteudo = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    autor = db.relationship('Usuario', backref='comentarios')
    musica = db.relationship('Music', backref='comentarios')
    


class Mensagem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    conteudo = db.Column(db.Text, nullable=False)
    data_envio = db.Column(db.DateTime, default=db.func.current_timestamp())

    # 🔹 Adiciona relacionamento com Usuario
    usuario = db.relationship('Usuario', backref='mensagens')
    

class Culto(db.Model):
    __tablename__ = 'cultos'
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Date, nullable=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

class CultoMusica(db.Model):
    __tablename__ = 'culto_musicas'
    id = db.Column(db.Integer, primary_key=True)
    culto_id = db.Column(db.Integer, db.ForeignKey('cultos.id'))
    musica_id = db.Column(db.Integer, db.ForeignKey('music.musica_id'))  # ou 'music.id' dependendo do modelo

class CultoEscala(db.Model):
    __tablename__ = 'culto_escala'
    id = db.Column(db.Integer, primary_key=True)
    culto_id = db.Column(db.Integer, db.ForeignKey('cultos.id'))
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))



@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Usuario, int(user_id))  # 🔹 Usa a sessão corretamente sem `with`
        
with app.app_context():
    db.create_all()

# 🔹 Rota inicial
@app.route('/')
def home():
    musicas_lista = Music.query.all()
    return render_template('index.html', musicas=musicas_lista)

# 🔹 Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form["usuario"]
        password = request.form["senha"].encode('utf-8')

        user = Usuario.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password.decode('utf-8')):
            login_user(user)
            session['login_sucesso'] = True  

            # 🔹 Se for membro, redireciona para `usuario.html`
            if user.role == "membro":
                return redirect(url_for("usuario"))

            # 🔹 Se for admin ou moderador, redireciona para `musicas.html`
            return redirect(url_for("musica"))

        else:
            flash("⚠️ Usuário ou senha inválidos!", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

# 🔹 Rota de registro de usuário
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nome = request.form['nome']
        sobrenome = request.form['sobrenome']
        telefone = request.form['telefone']
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        # 🛡️ Novos campos de segurança
        pergunta = request.form['pergunta_seguranca']
        resposta = request.form['resposta_seguranca']

        # 🔒 Verificação de duplicidade
        usuario_existente = Usuario.query.filter(
            (Usuario.nome == nome) | (Usuario.telefone == telefone)
        ).first()

        if usuario_existente:
            flash("⚠️ Já existe um usuário com esse nome ou telefone!", "danger")
            return redirect(url_for('register'))

        novo_usuario = Usuario(
            nome=nome,
            sobrenome=sobrenome,
            telefone=telefone,
            username=username,
            password=password,
            role="membro",
            pergunta_seguranca=pergunta,
            resposta_seguranca=resposta
        )

        db.session.add(novo_usuario)
        db.session.commit()
        flash("✅ Conta criada com sucesso! Faça login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

def is_moderador():
    return current_user.is_authenticated and current_user.role in ["admin", "moderador"]

# 🔹 Rota de músicas
@app.route('/musicas', methods=['GET','POST'])
@login_required
def musicas():
    if request.method == 'POST':
        if current_user.role not in ["cantor", "admin"]:  # 🔹 Agora administradores também podem adicionar músicas!
            flash("🚫 Apenas cantores e administradores podem adicionar músicas!", "danger")
            return redirect(url_for('musicas'))

        titulo = request.form.get('titulo')
        autor = request.form.get('autor')
        genero = request.form.get('genero')
        tom = request.form.get('tom')

        nova_musica = Music(
            titulo=titulo,
            autor=autor,
            genero=genero,
            tom=tom,
            usuario_id=current_user.id  # 🔹 Vinculamos ao cantor ou administrador que adicionou
        )
        db.session.add(nova_musica)
        db.session.commit()

        flash("✅ Música adicionada com sucesso!", "success")
    
    musicas_lista = Music.query.all()
    return render_template('musicas.html', musicas=musicas_lista)

@app.route('/excluir_musica/<int:musica_id>', methods=['POST'])
@login_required
def excluir_musica(musica_id):
    if current_user.role not in ["cantor", "admin"]:
        flash("🚫 Apenas cantores e administradores podem excluir músicas!", "danger")
        return redirect(url_for('musicas'))

    musica = Music.query.get_or_404(musica_id)
    db.session.delete(musica)
    db.session.commit()
    flash(f"✅ Música '{musica.titulo}' excluída com sucesso!", "success")
    return redirect(url_for('musicas'))

# 🔹 Rota de escala (corrigida)
@app.route('/escala', methods=['GET', 'POST'])
@login_required
def escala():
    if request.method == 'POST':
        componente = request.form.get('componente')
        dia = request.form.get('dia')
        horario = request.form.get('horario')

        if not componente or not dia or not horario:
            flash("Preencha todos os campos!", "warning")
            return redirect(url_for('escala'))

        nova_escala = Escala(componente=componente, dia=dia, horario=horario)
        db.session.add(nova_escala)
        db.session.commit()

        flash("✅ Escala adicionada com sucesso!", "success")
        return redirect(url_for('escala'))

    escalas_lista = Escala.query.all()

    # ✅ Agrupando por data (dia) como string
    escalas_agrupadas = defaultdict(list)
    for escala in escalas_lista:
        chave = escala.dia  # já é string tipo '2025-09-14'
        escalas_agrupadas[chave].append(escala)

    return render_template('escala.html', escalas=escalas_lista, escalas_agrupadas=escalas_agrupadas)


# 🔹 Rota de usuário
@app.route("/usuario")
@login_required
def usuario():
    usuario = current_user  # 🔹 Obtém o usuário logado
    musicas = Music.query.filter_by(usuario_id=usuario.id).all()  # 🔹 Filtra músicas do usuário
    return render_template("usuario.html", usuario=usuario, musicas=musicas)

# 🔹 Rota de logout
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('login_sucesso', None)
    logout_user()
    flash("👋 Você saiu da conta.", "info")
    return redirect(url_for("login"))

# 🔹 Rota para exibir música corretamente
@app.route('/musica')
@login_required
def musica():
    musicas_lista = list(Music.query.all())  # 🔹 Corrigido para garantir lista válida
    return render_template('musicas.html', musicas=musicas_lista)

# 🔹 Função auxiliar para verificar se usuário é admin
def is_admin():
    return current_user.is_authenticated and current_user.role == "admin"

@app.route('/gerenciar_usuarios')
@login_required
def gerenciar_usuarios():
    if current_user.role != "admin":  # 🔹 Apenas administradores podem acessar
        flash("Apenas administradores podem gerenciar usuários!", "danger")
        return redirect(url_for('musicas'))

    usuarios_lista = Usuario.query.all()  # 🔹 Busca todos os usuários
    return render_template('gerenciar_usuarios.html', usuarios=usuarios_lista)

@app.route('/atualizar_status_todas', methods=['POST'])
@login_required
def atualizar_status_todas():
    if current_user.role not in ["cantor", "admin"]:
        return jsonify({"erro": "Permissão negada"}), 403

    for musica in Music.query.all():
        musica_id_str = f"status_{musica.musica_id}"
        status_atualizado = request.form.get(musica_id_str) is not None
        musica.ensaiada = status_atualizado

    db.session.commit()

    # Retorna a lista atualizada com data_ensaio incluída
    musicas_json = []
    for musica in Music.query.all():
        musicas_json.append({
            "id": musica.musica_id,
            "titulo": musica.titulo,
            "ensaiada": musica.ensaiada,
            "data_ensaio": musica.data_ensaio.strftime('%d/%m/%Y') if musica.data_ensaio else "Sem data definida"
        })

    return jsonify({"musicas": musicas_json})  # Agora com a data!

@app.route('/promover_usuario/<int:user_id>', methods=['POST'])
@login_required
def promover_usuario(user_id):
    if not is_admin():  # 🔹 Garante que apenas administradores possam promover usuários
        flash("🚫 Apenas administradores podem promover usuários!", "danger")
        return redirect(url_for('gerenciar_usuarios'))

    usuario = Usuario.query.get_or_404(user_id)
    usuario.role = "admin"  # 🔹 Atualiza o nível de acesso
    db.session.commit()

    flash(f"✅ O usuário '{usuario.username}' agora é administrador!", "success")
    return redirect(url_for('gerenciar_usuarios'))

@app.route('/remover_usuario/<int:user_id>', methods=['POST'])
@login_required
def remover_usuario(user_id):
    if not is_admin():  # 🔹 Garante que apenas administradores possam remover usuários
        flash("🚫 Apenas administradores podem remover usuários!", "danger")
        return redirect(url_for('gerenciar_usuarios'))

    usuario = Usuario.query.get_or_404(user_id)

    db.session.delete(usuario)
    db.session.commit()

    flash(f"✅ O usuário '{usuario.username}' foi removido com sucesso!", "success")
    return redirect(url_for('gerenciar_usuarios'))


@app.route('/excluir_escala/<int:escala_id>', methods=['POST'])
@login_required
def excluir_escala(escala_id):
    if current_user.role not in ["cantor", "admin"]:  # 🔹 Agora cantores também podem excluir
        flash("🚫 Apenas cantores e administradores podem excluir escalas!", "danger")
        return redirect(url_for('escala'))

    escala = Escala.query.get_or_404(escala_id)
    db.session.delete(escala)
    db.session.commit()

    flash(f"✅ O componente '{escala.componente}' foi removido da escala!", "success")
    return redirect(url_for('escala'))


@app.route('/rebaixar_usuario/<int:user_id>', methods=['POST'])
@login_required
def rebaixar_usuario(user_id):
    if not is_admin():  # 🔹 Garante que apenas administradores possam modificar papéis de usuários
        flash("🚫 Apenas administradores podem modificar papéis de usuários!", "danger")
        return redirect(url_for('gerenciar_usuarios'))

    usuario = Usuario.query.get_or_404(user_id)
    usuario.role = "membro"  # 🔹 Rebaixa o usuário para membro
    db.session.commit()

    flash(f"✅ O usuário '{usuario.username}' foi rebaixado para Membro!", "success")
    return redirect(url_for('gerenciar_usuarios'))


@app.route('/obter_escalas_por_data', methods=['GET'])
@login_required
def obter_escalas_por_data():
    data_selecionada = request.args.get('data')

    if not data_selecionada:
        return jsonify({"erro": "Data não fornecida"}), 400

    escalas_lista = Escala.query.filter(Escala.dia == data_selecionada).all()

    escalas_json = []
    for escala in escalas_lista:
        escalas_json.append({
            "componente": escala.componente,
            "horario": escala.horario,
            "dia": escala.dia  # 🔹 Agora retorna corretamente a data!
        })

    return jsonify({"escalas": escalas_json})

@app.route('/promover_cantor/<int:user_id>', methods=['POST'])
@login_required
def promover_cantor(user_id):
    if not is_admin():  # 🔹 Apenas administradores podem promover cantores
        flash("🚫 Apenas administradores podem promover usuários a cantores!", "danger")
        return redirect(url_for('gerenciar_usuarios'))

    usuario = Usuario.query.get_or_404(user_id)
    usuario.role = "cantor"  # 🔹 Atualiza o papel do usuário para cantor
    db.session.commit()

    flash(f"✅ O usuário '{usuario.username}' agora é Cantor!", "success")
    return redirect(url_for('gerenciar_usuarios'))


@app.route('/alternar_cantor/<int:user_id>', methods=['POST'])
@login_required
def alternar_cantor(user_id):
    if not is_admin():  # 🔹 Apenas administradores podem modificar esse status
        flash("🚫 Apenas administradores podem modificar o status de cantor!", "danger")
        return redirect(url_for('gerenciar_usuarios'))

    usuario = Usuario.query.get_or_404(user_id)

    if usuario.role == "cantor":
        usuario.role = "membro"  # 🔹 Revoga status de cantor
        flash(f"🔻 O usuário '{usuario.username}' **não é mais Cantor**!", "warning")
    else:
        usuario.role = "cantor"  # 🔹 Promove a cantor
        flash(f"✅ O usuário '{usuario.username}' agora é Cantor!", "success")

    db.session.commit()
    return redirect(url_for('gerenciar_usuarios'))

@app.route('/obter_musicas', methods=['GET'])
@login_required
def obter_musicas():
    musicas_lista = Music.query.all()
    musicas_json = []

    for musica in musicas_lista:
        usuario = db.session.get(Usuario, musica.usuario_id) if musica.usuario_id else None
        nome_cantor = usuario.nome if usuario else "Desconhecido"

        musicas_json.append({
            "titulo": musica.titulo,
            "autor": musica.autor,
            "genero": musica.genero,
            "tom": musica.tom,
            "cantor": nome_cantor,
            "ensaiada": musica.ensaiada,
            "data_ensaio": musica.data_ensaio.strftime('%d/%m/%Y') if musica.data_ensaio else "Sem data definida",
        })

    return jsonify({"musicas": musicas_json})


@app.route("/comentarios/<int:musica_id>", methods=["GET"])
@login_required
def comentarios_musica(musica_id):
    comentarios = Comentario.query.filter_by(musica_id=musica_id).order_by(Comentario.timestamp.asc()).all()
    comentarios_json = []
    for c in comentarios:
        comentarios_json.append({
            "autor": c.autor.nome,
            "conteudo": c.conteudo,
            "data": c.timestamp.strftime("%d/%m/%Y %H:%M")
        })
    return jsonify(comentarios_json)

@app.route("/enviar_comentario", methods=["POST"])
@login_required
def enviar_comentario():
    data = request.json
    musica_id = data.get("musica_id")
    conteudo = data.get("conteudo")

    novo = Comentario(musica_id=musica_id, autor_id=current_user.id, conteudo=conteudo)
    db.session.add(novo)
    db.session.commit()
    return jsonify({"mensagem": "Comentário enviado!"}), 201

@app.route("/mensagens", methods=["GET"])
@login_required
def mensagens():
    mensagens = Mensagem.query.order_by(Mensagem.data_envio.desc()).all()
    mensagens_json = [{"id": m.id, "autor": m.usuario.nome, "conteudo": m.conteudo, "data": m.data_envio.strftime("%d/%m/%Y %H:%M")} for m in mensagens]
    return jsonify(mensagens_json)

@app.route('/enviar_mensagem', methods=['POST'])
def enviar_mensagem():
    if not current_user.is_authenticated:  # 🔹 Verifica se o usuário está logado
        return jsonify({"error": "Usuário não autenticado"}), 403  

    data = request.json
    nova_mensagem = Mensagem(
        usuario_id=current_user.id,  # 🔹 Agora armazenamos o ID do usuário logado
        conteudo=data.get("conteudo")
    )

    db.session.add(nova_mensagem)
    db.session.commit()

    return jsonify({"success": "Mensagem enviada com sucesso!"})

from flask_login import login_required, current_user

@app.route('/mensagens', methods=['GET'])
def obter_mensagens():
    mensagens = (
        Mensagem.query
        .join(Usuario, Usuario.id == Mensagem.usuario_id)
        .order_by(Mensagem.data_envio.desc())  # ✅ usa o campo correto
        .all()
    )

    mensagens_formatadas = [{
        "autor": mensagem.usuario.nome,
        "conteudo": mensagem.conteudo,
        "data": mensagem.data_envio.strftime("%d/%m/%Y %H:%M")
    } for mensagem in mensagens]

    return jsonify(mensagens_formatadas)

@app.route('/caixa_entrada', methods=['GET'])
@login_required
def caixa_entrada():
    mensagens = Mensagem.query.join(Usuario, Usuario.id == Mensagem.usuario_id).order_by(Mensagem.data_envio.desc()).all()

    mensagens_formatadas = [{
        "autor": mensagem.usuario.nome,  # 🔹 Agora pegamos o nome corretamente
        "conteudo": mensagem.conteudo,
        "data": mensagem.data_envio.strftime("%d/%m/%Y %H:%M")
    } for mensagem in mensagens]

    return jsonify(mensagens_formatadas)

@app.route("/salvar_data_ensaio/<int:musica_id>", methods=["POST"])
def salvar_data_ensaio(musica_id):
    data = request.json.get("data_ensaio")

    if not data:
        return jsonify({"erro": "Nenhuma data enviada!"}), 400

    try:
        data_formatada = datetime.strptime(data, "%Y-%m-%d")  # 🔹 Converte string para datetime
    except ValueError:
        return jsonify({"erro": "Formato de data inválido! Use AAAA-MM-DD."}), 400

    musica = Music.query.get(musica_id)
    if musica:
        musica.data_ensaio = data_formatada  # 🔹 Agora salvamos um objeto datetime válido!
        db.session.commit()
        return jsonify({"mensagem": "Data do ensaio salva!"}), 200

    return jsonify({"erro": "Música não encontrada!"}), 404



@app.route('/salvar_culto', methods=['POST'])
@login_required
def salvar_culto():
    try:
        dados = request.get_json()
        print("📥 Dados recebidos:", dados)

        data_culto = datetime.strptime(dados['data_culto'], '%Y-%m-%d').date()
        novo = Culto(data=data_culto)
        db.session.add(novo)
        db.session.commit()

        for musica_id in dados.get('musicas', []):
            print(f"🎵 Vinculando música ID: {musica_id}")
            db.session.add(CultoMusica(culto_id=novo.id, musica_id=int(musica_id)))

        for usuario_id in dados.get('escala', []):
            print(f"👤 Vinculando usuário ID: {usuario_id}")
            db.session.add(CultoEscala(culto_id=novo.id, usuario_id=int(usuario_id)))

        db.session.commit()

        musicas_titulos = [m.titulo for m in Music.query.filter(Music.musica_id.in_(dados["musicas"]))]
        escala_nomes = [u.username for u in Usuario.query.filter(Usuario.id.in_(dados["escala"]))]

        print("✅ Culto salvo com sucesso.")
        return jsonify({
            "mensagem": "Culto salvo!",
            "data": novo.data.strftime('%d/%m/%Y'),
            "musicas": musicas_titulos,
            "escala": escala_nomes
        })

    except Exception as e:
        import traceback
        print("❌ Erro ao salvar culto:")
        traceback.print_exc()
        return jsonify({"erro": "Falha ao salvar o culto."}), 500

@app.route("/cultos")
@login_required
def cultos():
    cultos = Culto.query.order_by(Culto.data.desc()).all()
    lista = []
    for culto in cultos:
        musicas_culto = db.session.query(Music).join(CultoMusica, Music.musica_id == CultoMusica.musica_id).filter(CultoMusica.culto_id == culto.id).all()
        escala_culto = db.session.query(Usuario).join(CultoEscala, Usuario.id == CultoEscala.usuario_id).filter(CultoEscala.culto_id == culto.id).all()
        lista.append({
            "culto": culto,
            "musicas": musicas_culto,
            "escala": escala_culto
        })

    musicas = Music.query.all()
    usuarios = Usuario.query.all()

    return render_template("cultos.html", lista_cultos=lista, musicas=musicas, usuarios=usuarios)

@app.route("/cultos_usuario")
@login_required
def cultos_usuario():
    cultos = Culto.query.order_by(Culto.data.desc()).all()
    resultado = []

    for culto in cultos:
        musicas = db.session.query(Music).join(CultoMusica).filter(CultoMusica.culto_id == culto.id).all()
        escala = db.session.query(Usuario).join(CultoEscala).filter(CultoEscala.culto_id == culto.id).all()

        if not musicas and not escala:
            continue

        resultado.append({
            "data": culto.data.strftime("%d/%m/%Y"),
            "musicas": [{"titulo": m.titulo, "tom": m.tom} for m in musicas],
            "escala": [f"{u.nome} ({u.role})" for u in escala]
        })

    return jsonify(resultado)
@app.route('/atualizar_status_musica/<int:musica_id>', methods=['POST'])
@login_required
def atualizar_status_musica(musica_id):
    if current_user.role not in ["cantor", "admin"]:
        return jsonify({"erro": "Permissão negada"}), 403

    musica = Music.query.get(musica_id)
    if not musica:
        return jsonify({"erro": "Música não encontrada"}), 404

    data = request.get_json()
    nova_situacao = data.get("ensaiada")

    musica.ensaiada = nova_situacao
    db.session.commit()

    return jsonify({
        "mensagem": "Status atualizado com sucesso",
        "data_ensaio": musica.data_ensaio.strftime('%d/%m/%Y') if musica.data_ensaio else ""
    })
    
@app.route('/remover_escala_culto', methods=['POST'])
@login_required
def remover_escala_culto():
    culto_id = request.form.get('culto_id')
    usuario_id = request.form.get('usuario_id')

    escala = CultoEscala.query.filter_by(culto_id=culto_id, usuario_id=usuario_id).first()
    if escala:
        db.session.delete(escala)
        db.session.commit()
        flash("🗑️ Membro removido da escala com sucesso!", "success")
    else:
        flash("❌ Escala não encontrada!", "danger")

    return redirect(url_for('cultos'))

@app.route('/remover_musica_culto', methods=['POST'])
@login_required
def remover_musica_culto():
    culto_id = request.form.get('culto_id')
    musica_id = request.form.get('musica_id')

    registro = CultoMusica.query.filter_by(culto_id=culto_id, musica_id=musica_id).first()
    if registro:
        db.session.delete(registro)
        db.session.commit()
        flash("🎵 Música removida do culto com sucesso!", "success")
    else:
        flash("❌ Música não encontrada nessa escala!", "danger")

    return redirect(url_for('cultos'))




@app.route('/recuperar_senha', methods=['GET', 'POST'])
def recuperar_senha():
    if request.method == 'POST':
        username = request.form['username']
        usuario = Usuario.query.filter_by(username=username).first()

        if usuario:
            return render_template('pergunta_seguranca.html', usuario=usuario)
        else:
            flash('⚠️ Usuário não encontrado.', 'danger')
            return redirect(url_for('recuperar_senha'))

    return render_template('recuperar_senha.html')

@app.route('/validar_resposta/<int:usuario_id>', methods=['POST'])
def validar_resposta(usuario_id):
    usuario = Usuario.query.get(usuario_id)
    resposta = request.form['resposta']

    if usuario and resposta.lower().strip() == usuario.resposta_seguranca.lower().strip():
        return render_template('nova_senha.html', usuario=usuario)
    else:
        flash('Resposta incorreta.')
        return redirect(url_for('recuperar_senha'))
    
import re  # no topo do arquivo, se ainda não tiver

@app.route('/trocar_senha/<int:usuario_id>', methods=['POST'])
def trocar_senha(usuario_id):
    nova_senha = request.form['nova_senha']
    confirmar_senha = request.form['confirmar_senha']
    usuario = Usuario.query.get(usuario_id)

    if not usuario:
        flash("⚠️ Usuário não encontrado.", "danger")
        return redirect(url_for('recuperar_senha'))

    # 🔐 Validação de força da senha
    if len(nova_senha) < 5:
        flash("❌ A senha deve ter no mínimo 5 caracteres.", "danger")
        return render_template('nova_senha.html', usuario=usuario)

    if not re.search(r'[A-Z]', nova_senha):
        flash("❌ A senha deve conter pelo menos uma letra maiúscula.", "danger")
        return render_template('nova_senha.html', usuario=usuario)

    if not re.search(r'\d', nova_senha):
        flash("❌ A senha deve conter pelo menos um número.", "danger")
        return render_template('nova_senha.html', usuario=usuario)

    # (Opcional) Verifica caractere especial
    # if not re.search(r'[!@#$%^&*(),.?":{}|<>]', nova_senha):
    #     flash("❌ A senha deve conter pelo menos um caractere especial.", "danger")
    #     return render_template('nova_senha.html', usuario=usuario)

    if nova_senha != confirmar_senha:
        flash("❌ As senhas não coincidem. Tente novamente.", "danger")
        return render_template('nova_senha.html', usuario=usuario)

    usuario.password = bcrypt.generate_password_hash(nova_senha).decode('utf-8')
    db.session.commit()
    flash("✅ Senha redefinida com sucesso! Faça login.", "success")
    return redirect(url_for('login'))


@app.route('/gerar_pdf_musicas', methods=['POST'])
def gerar_pdf_musicas():
    data = request.get_json()
    musicas_raw = data.get("musicas", [])

    # ✅ Imprime para depuração
    print("🎵 Músicas recebidas:", musicas_raw)

    # ✅ Reformatar os dados para garantir compatibilidade com o template
    musicas = []
    for m in musicas_raw:
        musica_formatada = {
            "titulo": m.get("titulo", ""),
            "autor": m.get("autor", ""),
            "genero": m.get("genero", ""),
            "tom": m.get("tom", ""),
            "status": m.get("status", ""),
            "data_ensaio": m.get("data_ensaio", ""),
            "cantor": m.get("cantor", "Desconhecido")
        }
        musicas.append(musica_formatada)

    html = render_template("ensaio_musica_pdf.html", musicas=musicas)
    config = pdfkit.configuration(wkhtmltopdf=r"C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
    options = {
        "enable-local-file-access": "",
        "page-size": "A4",
        "encoding": "UTF-8",
        "margin-top": "10mm",
        "margin-bottom": "10mm",
        "margin-left": "10mm",
        "margin-right": "10mm"
    }
    pdf = pdfkit.from_string(html, False, configuration=config, options=options)

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=musicas_para_ensaio.pdf'
    return response

@app.route('/exportar_musicas_pdf')
@login_required
def exportar_musicas_pdf():
    # Extrai os parâmetros da URL
    filtros = request.args.to_dict()

    # Se quiser filtrar por músicas ensaiadas, use isso:
    mostrar_ensaiadas = "ensaiadas" in filtros
    mostrar_nao_ensaiadas = "nao_ensaiadas" in filtros

    query = Music.query

    if mostrar_ensaiadas and not mostrar_nao_ensaiadas:
        query = query.filter_by(ensaiada=True)
    elif mostrar_nao_ensaiadas and not mostrar_ensaiadas:
        query = query.filter_by(ensaiada=False)
    # Se ambos estiverem marcados, não filtra — mostra todas

    musicas_filtradas = query.all()

    musicas = []
    for musica in musicas_filtradas:
        musicas.append({
            "titulo": musica.titulo,
            "autor": musica.autor,
            "genero": musica.genero,
            "tom": musica.tom,
            "status": "Ensaiada" if musica.ensaiada else "Não ensaiada",
            "data_ensaio": musica.data_ensaio.strftime('%d/%m/%Y') if musica.data_ensaio else "Sem data",
            "cantor": Usuario.query.get(musica.usuario_id).nome if musica.usuario_id else "Desconhecido"
        })

    html = render_template("ensaio_musica_pdf.html", musicas=musicas)
    config = pdfkit.configuration(wkhtmltopdf=r"C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
    options = {
        "enable-local-file-access": "",
        "page-size": "A4",
        "encoding": "UTF-8",
        "margin-top": "10mm",
        "margin-bottom": "10mm",
        "margin-left": "10mm",
        "margin-right": "10mm"
    }
    pdf = pdfkit.from_string(html, False, configuration=config, options=options)

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=musicas_filtradas.pdf'
    return response





login_manager.init_app(app)

if __name__ == "__main__":
    app.run(debug=True)
    