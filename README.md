# AppRoteiros.Auth

[![.NET](https://img.shields.io/badge/.NET-8.0-blueviolet.svg)](https://dotnet.microsoft.com/)
[![Build](https://github.com/owner/AppRoteiros.Auth/actions/workflows/ci.yml/badge.svg)](https://github.com/owner/AppRoteiros.Auth/actions)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](#-licenca)

<!--
Substitua "owner" na URL acima pelo nome da sua conta/organização no GitHub.
Ex: walltravelbr/AppRoteiros.Auth
E ajuste o caminho do workflow (ci.yml) se usar outro nome.
-->

## 📌 Sobre o projeto

**AppRoteiros.Auth** é o serviço de autenticação oficial da plataforma **AppRoteiros**, responsável por:

- Gerenciar usuários
- Registrar contas
- Autenticar via JWT
- Renovar tokens com Refresh Token
- Proteger recursos da API
- Fornecer base para o painel Admin e para o App Mobile

Ele foi desenvolvido em **.NET 8**, utilizando **Identity**, **Entity Framework Core**, **JWT Bearer Authentication** e uma arquitetura simples e escalável.

---

## 🚀 Tecnologias utilizadas

- .NET 8 (ASP.NET MVC + API)
- Entity Framework Core 8
- ASP.NET Core Identity
- JWT (JSON Web Token)
- Refresh Tokens
- SQL Server LocalDB (ambiente de desenvolvimento)
- Postman Collection para testes

Organização por camadas:

- `Controllers`
- `Dtos`
- `Services`
- `Domain`
- `Config`
- `Data`

---

## 📁 Estrutura do projeto

```text
AppRoteiros.Auth.Web/
 ├── Controllers/
 │    ├── Api/
 │    │     ├── AuthController.cs
 │    │     └── UsersController.cs
 │
 ├── Dtos/
 │    ├── Auth/
 │    │     ├── RegisterRequest.cs
 │    │     ├── LoginRequest.cs
 │    │     ├── RefreshRequest.cs
 │    └── Users/
 │          └── UserProfileResponse.cs
 │
 ├── Domain/
 │    └── Entities/
 │         ├── ApplicationUser.cs
 │         └── RefreshToken.cs
 │
 ├── Services/
 │     ├── ITokenService.cs
 │     └── TokenService.cs
 │
 ├── Data/
 │     └── ApplicationDbContext.cs
 │
 ├── Config/
 │     └── JwtSettings.cs
 │
 ├── appsettings.json
 └── Program.cs