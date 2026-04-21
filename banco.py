import sqlite3

# Conecta ao banco de dados (se o arquivo não existir, ele será criado automaticamente)
conexao = sqlite3.connect('compressores.db')
cursor = conexao.cursor()

# Cria a tabela com todos os campos da folha de controle
cursor.execute('''
CREATE TABLE IF NOT EXISTS leituras (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data_leitura TEXT,
    hora_leitura TEXT,
    id_compressor TEXT,
    turno TEXT,
    pa REAL,
    po REAL,
    pd REAL,
    temperatura_oleo REAL,
    temperatura_descarga REAL,
    capacidade_pct INTEGER,
    responsavel TEXT,
    observacoes TEXT
)
''')

# Salva as alterações e fecha a conexão
conexao.commit()
conexao.close()

print("Banco de dados criado e configurado com sucesso!")