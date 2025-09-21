# CrowdSec_Scenario_ssh-scan

1. Crear archivo del escenario

Crea un archivo en:

/etc/crowdsec/scenarios/ssh-kex-mac-ban.yaml


Con este contenido:
```yaml
type: trigger
name: crowdsecurity/ssh-kex-mac-ban
description: "Banea 1 año las IPs que causen errores de kex_exchange_identification o no matching MAC en SSH"
filter: |
  evt.Parsed.program == "sshd" && (
    Upper(evt.Parsed.message) contains "KEX_EXCHANGE_IDENTIFICATION" ||
    Upper(evt.Parsed.message) contains "NO MATCHING MAC FOUND"
  )
groupby: evt.Meta.source_ip
blackhole: 1
labels:
  service: ssh
  type: bruteforce
```
2. Crear archivo de colección

Así CrowdSec sabrá incluir el escenario en ejecución:

/etc/crowdsec/collections/ssh-kex-mac-ban.yaml


Contenido:
```yaml
name: crowdsecurity/ssh-kex-mac-ban
description: "Colección que incluye el escenario de baneo de SSH con errores kex/MAC"
scenarios:
  - crowdsecurity/ssh-kex-mac-ban
```
3. Ajustar duración del ban

El escenario sólo genera alertas, el tiempo de baneo lo define la remediation.
Edita tu archivo de bouncers o de configuración de decisiones para que el ban dure 1 año (365 días).

Por ejemplo en /etc/crowdsec/profiles.yaml añade al inicio algo así:
```yaml
name: ssh-kex-mac-ban
filters:
 - Alert.Remediation == true && Alert.Scenario == "crowdsecurity/ssh-kex-mac-ban"
decisions:
 - type: ban
   duration: 8760h   # 365 días
on_success: break
```
4. Recargar CrowdSec

Aplica los cambios:

sudo systemctl reload crowdsec

5. Verificar funcionamiento

Haz una prueba forzando un log falso:

logger -p auth.err -t sshd "error: kex_exchange_identification: Connection closed by remote host"


y revisa:

sudo cscli alerts list


Deberías ver un alerta + decisión de ban sobre la IP de origen.
