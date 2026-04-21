import os
import io
import csv
import secrets
import logging
from datetime import timedelta

from flask import Flask, render_template, request, redirect, url_for, Response, session, flash, send_file
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)

# --- CAMINHO ABSOLUTO DO BANCO DE DADOS ---
PASTA_PROJETO = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(PASTA_PROJETO, 'compressores.db')

# --- SECRET KEY SEGURA (persistida em arquivo local, NUNCA no código-fonte) ---
def _get_or_create_secret_key():
    key_file = os.path.join(PASTA_PROJETO, '.secret_key')
    if os.path.exists(key_file):
        with open(key_file, 'r') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(key_file, 'w') as f:
        f.write(key)
    return key

app.secret_key = os.environ.get('SECRET_KEY') or _get_or_create_secret_key()

# --- SESSÃO COM EXPIRAÇÃO (8 horas) ---
app.permanent_session_lifetime = timedelta(hours=8)

# --- PROTEÇÃO CSRF GLOBAL ---
csrf = CSRFProtect(app)

# --- RATE LIMITING ---
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

# --- LOGGING SEGURO (erros internos vão pro log, não pro usuário) ---
logging.basicConfig(level=logging.ERROR)

def conectar():
    return sqlite3.connect(DB_PATH)

# --- AUTO-INICIALIZAÇÃO DO BANCO ---
def inicializar_banco():
    db = conectar()
    cursor = db.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS leituras (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data_leitura TEXT, hora_leitura TEXT, id_compressor TEXT, turno TEXT,
            pa TEXT, po TEXT, pd TEXT, temperatura_oleo TEXT, temperatura_descarga TEXT,
            capacidade_pct TEXT, responsavel TEXT, observacoes TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome_completo TEXT, login TEXT, senha TEXT, perfil TEXT DEFAULT 'Operador'
        )
    ''')
    
    try:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN perfil TEXT DEFAULT 'Operador'")
    except sqlite3.OperationalError:
        pass 
    
    # --- Criar admin padrão com SENHA ALEATÓRIA (exibida apenas uma vez no console) ---
    cursor.execute("SELECT 1 FROM usuarios WHERE login = 'admin'")
    if not cursor.fetchone():
        senha_padrao = secrets.token_urlsafe(12)
        hash_senha = generate_password_hash(senha_padrao)
        cursor.execute(
            "INSERT INTO usuarios (nome_completo, login, senha, perfil) VALUES (?, ?, ?, ?)",
            ('Administrador do Sistema', 'admin', hash_senha, 'Admin')
        )
        print(f"\n{'='*60}")
        print(f"  SENHA DO ADMINISTRADOR GERADA: {senha_padrao}")
        print(f"  Login: admin")
        print(f"  ANOTE ESTA SENHA! Ela não será exibida novamente.")
        print(f"{'='*60}\n")
    
    cursor.execute("UPDATE usuarios SET perfil = 'Admin' WHERE login = 'admin'")
    
    # --- Migrar senhas em texto plano para hash seguro ---
    _migrar_senhas_plaintext(cursor)
    
    db.commit()
    db.close()

def _migrar_senhas_plaintext(cursor):
    """Detecta senhas em texto plano e converte para hash seguro (executa uma vez)."""
    cursor.execute("SELECT id, senha FROM usuarios")
    for uid, senha in cursor.fetchall():
        # Senhas hasheadas pelo werkzeug começam com prefixos conhecidos
        if not senha.startswith(('scrypt:', 'pbkdf2:')):
            hash_novo = generate_password_hash(senha)
            cursor.execute("UPDATE usuarios SET senha = ? WHERE id = ?", (hash_novo, uid))

inicializar_banco()

# =======================================================================
# MIDDLEWARE DE SESSÃO — torna todas as sessões permanentes (com expiração)
# =======================================================================
@app.before_request
def _tornar_sessao_permanente():
    session.permanent = True

# =======================================================================
# ROTAS DE SEGURANÇA E GESTÃO
# =======================================================================

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    erro = None
    if request.method == 'POST':
        usuario_digitado = request.form.get('usuario', '').strip()
        senha_digitada = request.form.get('senha', '')

        db = conectar()
        cursor = db.cursor()
        cursor.execute("SELECT id, nome_completo, perfil, senha FROM usuarios WHERE login = ?", (usuario_digitado,))
        usuario_banco = cursor.fetchone()
        db.close()

        if usuario_banco and check_password_hash(usuario_banco[3], senha_digitada):
            session['logado'] = True
            session['nome_completo'] = usuario_banco[1]
            session['perfil'] = usuario_banco[2]
            return redirect(url_for('home'))
        else:
            erro = "Usuário ou senha incorretos!"

    return render_template('login.html', erro=erro)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/usuarios', methods=['GET', 'POST'])
def usuarios():
    if session.get('perfil') != 'Admin': 
        return redirect(url_for('home'))
    
    db = conectar()
    cursor = db.cursor()

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        login_novo = request.form.get('login', '').strip()
        senha = request.form.get('senha', '')
        perfil = request.form.get('perfil', 'Operador')

        if not nome or not login_novo or not senha:
            flash("Todos os campos são obrigatórios!", "danger")
        elif perfil not in ('Operador', 'Admin'):
            flash("Perfil inválido!", "danger")
        else:
            cursor.execute("SELECT 1 FROM usuarios WHERE login = ?", (login_novo,))
            if cursor.fetchone():
                flash("Esse login já está em uso!", "danger")
            else:
                hash_senha = generate_password_hash(senha)
                db.execute("INSERT INTO usuarios (nome_completo, login, senha, perfil) VALUES (?, ?, ?, ?)",
                           (nome, login_novo, hash_senha, perfil))
                db.commit()
                flash("Usuário criado com sucesso!", "success")
    
    cursor.execute("SELECT id, nome_completo, login, perfil FROM usuarios")
    lista_usuarios = cursor.fetchall()
    db.close()
    
    return render_template('usuarios.html', usuarios=lista_usuarios)

@app.route('/excluir_usuario/<int:id>', methods=['POST'])
def excluir_usuario(id):
    if session.get('perfil') == 'Admin':
        db = conectar()
        cursor = db.cursor()
        cursor.execute("SELECT login FROM usuarios WHERE id = ?", (id,))
        usuario = cursor.fetchone()
        if usuario and usuario[0] == 'admin':
            flash("Não é possível excluir o administrador principal!", "danger")
        else:
            db.execute("DELETE FROM usuarios WHERE id = ?", (id,))
            db.commit()
            flash("Usuário excluído!", "warning")
        db.close()
    return redirect(url_for('usuarios'))

# --- DOWNLOAD DO BACKUP DO BANCO DE DADOS ---
@app.route('/backup')
def backup():
    if session.get('perfil') == 'Admin':
        try:
            return send_file(DB_PATH, as_attachment=True, download_name='backup_compressores.db')
        except Exception as e:
            app.logger.error(f"Erro ao gerar backup: {str(e)}")
            flash("Erro interno ao gerar backup. Tente novamente.", "danger")
            return redirect(url_for('home'))
    return redirect(url_for('home'))

# =======================================================================
# ROTAS DO SISTEMA
# =======================================================================

@app.route('/')
def home():
    if 'logado' not in session: return redirect(url_for('login'))
    return render_template('index.html', nome_usuario=session['nome_completo'], perfil=session['perfil'])

@app.route('/salvar', methods=['POST'])
def salvar():
    if 'logado' not in session: return redirect(url_for('login'))

    f = request.form
    hora_leitura = f.get('hora_leitura', '')
    
    try:
        hora_int = int(hora_leitura.split(':')[0])
    except (ValueError, AttributeError, IndexError):
        flash("Formato de hora inválido!", "danger")
        return redirect(url_for('home'))

    if 0 <= hora_int < 6: turno = "1º Turno"
    elif 6 <= hora_int < 12: turno = "2º Turno"
    elif 12 <= hora_int < 18: turno = "3º Turno"
    else: turno = "4º Turno"

    db = conectar()
    db.execute('''
        INSERT INTO leituras (
            data_leitura, hora_leitura, id_compressor, turno, pa, po, pd,
            temperatura_oleo, temperatura_descarga, capacidade_pct, responsavel, observacoes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (f.get('data_leitura'), hora_leitura, f.get('id_compressor'), turno, f.get('pa'), f.get('po'), f.get('pd'),
        f.get('temperatura_oleo'), f.get('temperatura_descarga'), f.get('capacidade_pct'), session['nome_completo'], f.get('observacoes')))
    db.commit()
    db.close()
    
    flash(f"Leitura do Compressor {f.get('id_compressor')} registrada com sucesso!", "success")
    return redirect(url_for('home'))

@app.route('/historico')
def historico():
    if 'logado' not in session: return redirect(url_for('login'))
    db = conectar()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM leituras ORDER BY id DESC')
    leituras_banco = cursor.fetchall()
    db.close()
    return render_template('historico.html', leituras=leituras_banco, perfil=session['perfil'])

@app.route('/excluir_leitura/<int:id>', methods=['POST'])
def excluir_leitura(id):
    if session.get('perfil') == 'Admin':
        db = conectar()
        db.execute("DELETE FROM leituras WHERE id = ?", (id,))
        db.commit()
        db.close()
        flash("Leitura apagada do histórico!", "warning")
    return redirect(url_for('historico'))

@app.route('/dashboard')
def dashboard():
    if 'logado' not in session: return redirect(url_for('login'))
    comp_filtro = request.args.get('compressor', '')
    data_inicio = request.args.get('data_inicio', '')
    data_fim = request.args.get('data_fim', '')

    db = conectar()
    cursor = db.cursor()
    query = "SELECT data_leitura, hora_leitura, id_compressor, pa, po, pd, temperatura_oleo, temperatura_descarga, capacidade_pct FROM leituras WHERE 1=1"
    params = []

    if comp_filtro:
        query += " AND id_compressor = ?"
        params.append(comp_filtro)
    if data_inicio:
        query += " AND data_leitura >= ?"
        params.append(data_inicio)
    if data_fim:
        query += " AND data_leitura <= ?"
        params.append(data_fim)

    query += " ORDER BY id ASC LIMIT 50"
    cursor.execute(query, params)
    dados = cursor.fetchall()
    db.close()

    labels = [f"{d[0]} {d[1]}" for d in dados]
    pa_list = [d[3] for d in dados]; po_list = [d[4] for d in dados]; pd_list = [d[5] for d in dados]
    to_list = [d[6] for d in dados]; td_list = [d[7] for d in dados]; cap_list = [d[8] for d in dados]

    return render_template('dashboard.html', labels=labels, pa=pa_list, po=po_list, pd=pd_list, to=to_list, td=td_list, cap=cap_list, comp_selecionado=comp_filtro)

@app.route('/exportar')
def exportar():
    if 'logado' not in session: return redirect(url_for('login'))
    db = conectar()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM leituras ORDER BY id DESC')
    leituras = cursor.fetchall()
    db.close()

    si = io.StringIO()
    cw = csv.writer(si, delimiter=';') 
    cw.writerow(['ID', 'Data', 'Hora', 'Compressor', 'Turno', 'PA (bar)', 'PO (bar)', 'PD (bar)', 'TO (ºC)', 'TD (ºC)', 'Capacidade (%)', 'Responsavel', 'Observacoes'])
    cw.writerows(leituras)
    output = '\ufeff' + si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=relatorio_compressores.csv"})

if __name__ == '__main__':
    # Mantido host='0.0.0.0' para a rede da fábrica (Wi-Fi), com debug=False para segurança.
    app.run(debug=False, host='0.0.0.0')