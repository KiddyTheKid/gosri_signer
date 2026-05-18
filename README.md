# gosri_signer

**gosri_signer** es un programa diseñado para la simplicidad y el uso rápido desde cualquier otro programa o lenguaje que requiera firmar documentos XML para el sistema de Facturación Electrónica del **SRI (Servicio de Rentas Internas) del Ecuador**. 

Está pensado para ser integrado fácilmente como una herramienta de línea de comandos, quitando al usuario la pesada carga de tener que investigar e implementar algoritmos criptográficos, canonicalizaciones complejas y el estándar de firmas XAdES-BES del SRI en su lenguaje de programación de preferencia (PHP, Python, Node.js, Ruby, Java, etc).

## Características

- Soporta el estándar exigido por el SRI: **XAdES-BES** y firmas *enveloped* sobre comprobantes electrónicos.
- Lee y carga certificados de firma digital **.p12** de Entidades de Certificación Ecuatorianas (BCE, SecurityData, ANF, etc).
- Interfaz CLI simple que se comunica mediante `stdout` (salida estándar), lo cual permite una fácil redirección hacia archivos o captura de memoria desde lenguajes externos.
- Escrito en **Go** para lograr máxima rapidez y portabilidad. Puedes compilarlo en un único binario que no requiere de dependencias del sistema operativo.

## Requisitos

- [Go (Golang)](https://go.dev/dl/) instalado en tu equipo si deseas compilarlo desde el código fuente.
- Un certificado digital vigente en formato P12 (Personal Natural o Representante Legal).
- La contraseña del archivo P12.

## Compilación

Para generar el binario ejecutable de forma nativa en tu sistema (ya sea Windows, Linux o macOS), clona o descarga este repositorio y ejecuta:

```bash
go build -o gosri_signer signer.go
```

Esto generará el archivo `gosri_signer` (`gosri_signer.exe` en Windows) que ya puedes distribuir sin requerir la instalación de Go en el sistema destino.

## Uso

La sintaxis del comando es la siguiente:

```bash
./gosri_signer <input.xml> <cert.p12> <password>
```

El resultado de la ejecución arrojará el XML completamente firmado y canonizado hacia la salida estándar (consola). Si ocurre un error, el programa devolverá código de salida `1` y arrojará el error a la salida de errores (`stderr`).

### Ejemplos

**1. Firmar un archivo y guardar la respuesta en uno nuevo (vía consola):**

Puedes usar el operador de redirección `>` de la terminal:

```bash
./gosri_signer factura_sin_firmar.xml mi_firma.p12 "mi_contraseña_123" > factura_firmada.xml
```

**2. Uso desde PHP (`shell_exec` o `exec`):**

```php
$comando = './gosri_signer factura.xml firma.p12 "12345"';
$xmlFirmado = shell_exec($comando);

if ($xmlFirmado === null) {
    echo "Hubo un error al firmar.";
} else {
    file_put_contents('factura_firmada.xml', $xmlFirmado);
}
```

**3. Uso desde Node.js (`exec`):**

```javascript
const { exec } = require('child_process');

exec('./gosri_signer factura.xml firma.p12 "12345"', (error, stdout, stderr) => {
  if (error) {
    console.error(`Error al firmar: ${error.message}`);
    return;
  }
  if (stderr) {
    console.error(`stderr: ${stderr}`);
    return;
  }
  
  // El XML firmado está en 'stdout'
  console.log(stdout);
});
```

**4. Uso desde Python (`subprocess`):**

```python
import subprocess

resultado = subprocess.run(
    ['./gosri_signer', 'factura.xml', 'firma.p12', '12345'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

if resultado.returncode == 0:
    xml_firmado = resultado.stdout
    with open('factura_firmada.xml', 'w') as f:
        f.write(xml_firmado)
else:
    print(f"Error: {resultado.stderr}")
```

## Licencia

Este software se rige bajo la Licencia Pública General de GNU (GPLv3). Revisa el archivo `LICENSE.txt` para más detalles.
