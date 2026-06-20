Dado o escopo abaixo:

- `*.target.com`
- `10.10.1.1`

Examine recursivamente o conteúdo de todos arquivos da pasta $RECON_FOLDER. Com base no conteúdo execute as tarefas a baixo e crie um arquivo markdown `$RECON_FOLDER/summary.md` com o resultado.

### Subdomínios

1. Sumarize os subdomínios ativos que aparentam ser mais vulneráveis com base no nome do subdomínio.

2. Sumarize os subdomínios ativos que aparentam ser mais sensíveis com base no nome do subdomínio.
   
3. Caractegorize os subdomínios em categorias como autenticação, administrativa, api, interno, dentre outros.
   
### Infraestrutura

1. Sumarize os endereços ips dos hosts que apresentam ser mais vulneráveis com base nos serviços sendo executas e suas respectivas versões ou banners.

2.  Sumarize os endereços ips dos hostsque aparentam ser mais sensíveis com base nos serviços sendo executas e suas respectivas versões ou banners.
   
### DNS

1. Sumarize os subdomínios que possivelmente são vulneráveis a Email Spoofing e Subdomain Takeover.
   
### Tecnologias

1. Examine se alguma tecnologia utilizada nos alvos são de alguma versão vulnerável. 
   
2. Faça um resumo das tecnologias mais usadas pela empresa.
   
3. Sugira quais são as vulnerabilidades mais encontradas nestas tecnologias.
   
4. Sumarize os subdomínios ativos que aparentam ser mais vulneráveis com base nas suas tecnologias e respectivas versões.

5. Sumarize os subdomínios ativos que aparentam ser mais sensíveis com base nas suas tecnologias e respectivas versões.
   
6. Procure por informações sensíveis (token, email, user, pii, password) no conteúdo dos HTMLs dos alvos.
 
### Javascript 

1. Procure por vulnerabilidades client side nos arquivos javascript.
   
2. Procure por informações sensíveis (token, email, user, pii, password, csrf_token) no conteúdo dos arquivos javascript dos alvos.

3. Examine todos os javascripts e procure os subdomínios ativos que aparentam ser mais vulneráveis com base na robustês dos arquivos javascript.
   
4. Examine todos os javascripts e procure os subdomínios ativos que aparentam ser mais sensíveis com base na lógica dos arquivos javascript.

5. Procure por endpoints de Graphql e Websocket nos arquivos.

### URLs e Fuzzing

1. Sumarize as urls e caminhos que tenho acesso e aparentam ser mais vulneráveis com base nos seus nomes.
   
2. Sumarize as urls e caminhos que tenho acesso e aparentam ser mais sensíveis com base nos seus nomes.

### Outros

1. Nesta seção retorno qualquer outro resultado interessante para um pentest autorizado que ainda não foi contemplado nas seções anteriores.

Não performe nenhum ataque. Não envie nenhuma requisição. Por hora só quero examinar os resultados contidos nesta pasta.