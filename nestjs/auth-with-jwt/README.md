# Modulo de Auth de nest

## Controlador
Rutas:
- /register
- /login
- /logout
- /refresh-tokens

## Service
Con las funciones necesarias

## Module
Con todo importado y el jwtModule configurado

## AuthGuard
Implementado completamente usando los metodos del JwtManagerService

## JwtManagerService
Servicio con multiples funciones para el manejo, validacion y gestion en base de datos de los jwt.

> Los JWT son almacenados en cookies, el JwtManagerService contiene un metodo para leerlas tambien desde los headers si fuera necesario.

El acceso a la DB es utilizando Prisma, con el PrismaService

## Pasos para funcionar:
- Configurar correctamente las variables de entorno y las variables del tiempo de expiracion y el nombre de las cookies y los headers de los JWT
- Definir el `login.dto` y el `register.dto`
- Ajustar el ORM y las funciones que lo utilizan segun el proyecto
