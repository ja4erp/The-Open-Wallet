# The Open Wallet

**The Open Wallet** es una herramienta de línea de comandos (CLI) para gestionar billeteras de Ethereum. Permite crear, importar y gestionar billeteras, consultar saldos y enviar ETH de manera segura. El programa ofrece protección adicional mediante autenticación de dos factores (2FA).

## Características

- **Crear Billetera**: Genera una nueva billetera de Ethereum, encriptada y segura.
- **Consultar Saldo**: Consulta el saldo de una billetera de Ethereum.
- **Enviar ETH**: Envía ETH a otra dirección.
- **Modo Desarrollador**: Accede a opciones avanzadas como ver la clave privada y configurar 2FA.
- **Autenticación de Dos Factores (2FA)**: Protege la información sensible con una capa adicional de seguridad.

## Instalación

1. **Clona el Repositorio**

   Clona el repositorio a tu máquina local:
   ```bash
   git clone https://github.com/ja4erp/The-Open-Wallet.git
   ```

2. **Instala Dependencias**

   Navega al directorio del proyecto e instala las dependencias necesarias:
   ```bash
   cd The-Open-Wallet
   npm i
   ```

## Uso

1. **Iniciar el Programa**

   Ejecuta el programa con:
   ```bash
   node index.mjs
   ```

   La primera vez que ejecutes el programa, se te pedirá que configures una contraseña para el programa si aún no se ha configurado.

2. **Menú Principal**

   Al iniciar el programa, se te presentará un menú con las siguientes opciones:
   - **Crear Billetera**: Genera una nueva billetera de Ethereum y la guarda de forma segura.
   - **Consultar Saldo**: Consulta el saldo de una billetera existente.
   - **Enviar ETH**: Envía ETH a otra dirección.
   - **Modo Desarrollador**: Accede a opciones avanzadas como ver la clave privada y configurar 2FA.
   - **Salir**: Cierra el programa.

3. **Modo Desarrollador**

   En el menú de desarrollador podrás:
   - **Ver Clave Privada**: Requiere autenticación 2FA. Muestra la clave privada de una billetera.
   - **Configurar 2FA**: Genera un nuevo código 2FA y muestra un código QR para escanear con una aplicación de autenticación.
   - **Importar Billetera**: Importa una billetera existente utilizando la clave privada.
   - **Volver al Menú Principal**: Regresa al menú principal.

## Configuración de 2FA

Para habilitar 2FA:
- En el menú de desarrollador, selecciona la opción "Configurar 2FA".
- Se generará un código secreto y un código QR. Escanea el QR con una aplicación de autenticación como Google Authenticator o Authy.
- Para acceder a las funciones que requieren 2FA, el programa te pedirá el código de tu aplicación 2FA.

## Seguridad

- **Contraseña del Programa**: Protege el acceso al programa. Se solicita al iniciar el programa.
- **Contraseña de la Billetera**: Protege la clave privada de cada billetera almacenada.
- **2FA**: Añade una capa adicional de seguridad para acciones sensibles y acceso al programa.

## Contribuciones

¡Las contribuciones son bienvenidas! Si encuentras errores o tienes ideas para nuevas características, siéntete libre de hacer un pull request o abrir un issue.

## Donaciones
Si te ha gustado **The Open Wallet** y deseas apoyar el desarrollo del proyecto, puedes hacer una donación en Ethereum. Tu apoyo es muy apreciado y ayuda a mantener el desarrollo y mantenimiento del software.

Dirección de donación: 0x09dec7eE0c8D07e195b256B5afBA22f41e90B975

## Licencia

Este proyecto está licenciado bajo la [Licencia MIT](LICENSE).
