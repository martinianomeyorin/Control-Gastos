# Control Gastos

App personal para registrar compras, cuotas, ingresos y disponibilidad mensual.

## Ejecutar

Requiere Node.js 18 o superior:

```sh
npm install
npm run dev
```

Abrí la dirección local que muestra Vite (normalmente http://localhost:5173).

## Registro y tarjeta

- Escribí una compra en lenguaje natural, revisá el importe, la descripción, la categoría y el medio de pago antes de guardarla.
- Para crédito, seleccioná YOY, Visa Galicia, Mastercard Galicia o Galicia Mas, e indicá la cantidad de cuotas.
- La app propone la primera cuota según el cierre de esa tarjeta en el mes de compra. El mes de inicio queda editable antes de guardar.
- Cada compra en cuotas se distribuye por mes. La última cuota ajusta centavos para que la suma coincida con el total.
- El resumen y la tabla muestran el importe que corresponde pagar en el mes elegido, y el panel de tarjetas separa lo que entra por tarjeta.
- Los cierres se configuran por tarjeta y por mes. Como referencias iniciales se usan los días 23 para YOY y 30 para Galicia, observados en el Excel; ambos se pueden cambiar.

## Finanzas del mes

Ingresá el sueldo, los cobros de internet y lo invertido para cada mes. El disponible se calcula así:

`saldo anterior + sueldo + cobros de internet - gastos del mes - inversiones`

El saldo se arrastra entre meses y años. El saldo inicial solo se ingresa en enero del primer año cargado.

Los datos se guardan localmente en el navegador. El archivo Excel original no se modifica ni se importa automáticamente.
