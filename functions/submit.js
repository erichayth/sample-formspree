/**
 * POST /api/submit
 */
const jose = require("jose");

export async function onRequestPost(context) {
    try {
        const request = context.request;
        const body = await request.formData();
        const token = body.get('cf-turnstile-response');
        const ip = request.headers.get('CF-Connecting-IP');
        const monocle_data = body.get('monocle');
        const privateKey = await jose.importPKCS8(context.env.SPUR_KEY, "ECDH-ES");

        // decrypted plaintext is a Buffer and will need decoding
        const decoder = new TextDecoder();
      
        // decrypt the bundle
        const decryptResult = await jose.compactDecrypt(monocle_data, privateKey);
      
        // decode the plaintext Buffer and parse back to JSON
        const threatBundleJson = JSON.parse(decoder.decode(decryptResult.plaintext));
      
        // Extract data from the threatBundleJson JSON data
        const { vpn, proxied, anon } = threatBundleJson;

        // Convert boolean values to "1" or "0"
        const vpnValue = vpn ? 1 : 0;
        const proxiedValue = proxied ? 1 : 0;
        const anonValue = anon ? 1 : 0;

        let formData = new FormData();
        formData.append('secret', context.env.CF_SECRET_KEY);
        formData.append('response', token);
        formData.append('remoteip', ip);

        const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
        const result = await fetch(url, { body: formData, method: 'POST' });
        const outcome = await result.json();

        if (!outcome.success) {
            throw new Error('Invalid request');
        }
        try {
            // Convert FormData to JSON
            let output = {};
            for (let [key, value] of body) {
              if (key !== 'cf-turnstile-response') {
                let tmp = output[key];
                if (tmp === undefined) {
                  output[key] = value;
                } else {
                  output[key] = [].concat(tmp, value);
                }
              }
            }
            output['timestamp'] = new Date().toISOString(); // Add a timestamp

            // Prepare SQL statement to insert data
            const sql = `
              INSERT INTO table2 (name, email, referers, movies, remoteip, timestamp, spur_vpn, spur_proxied, spur_anon)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            `;
            
            // Get data from the submitted JSON
            const { name, email, referers, movies, timestamp } = output;

            // Check if movies is an object and stringify it if it is
            let moviesString;
            if (typeof movies === 'object' && movies !== null) {
              moviesString = JSON.stringify(movies);
            } else {
              moviesString = movies;
            }

            // Execute SQL statement
            const { success } = await context.env.FORMSPREE.prepare(sql)
                .bind(name, email, referers, moviesString, ip, timestamp, vpnValue, proxiedValue, anonValue)
                .run()
            console.log('Success:', success);

            // Check if vpnValue, proxiedValue, or anonValue is "1"
            if (vpnValue === 1 || proxiedValue === 1 || anonValue === 1) {
            return new Response('Forbidden', { status: 403 });
            }
            // Return a successful response
            return new Response('Submission successful', {
              headers: {
                'Content-Type': 'text/plain;charset=utf-8',
              },
            });
          } catch (err) {
            return new Response(err.message, { status: 400 });
          }
        }
        catch (err) {
            return new Response(err.message || err.toString(), { status: 500 });
        }
}
