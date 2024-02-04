/**
 * POST /api/submit
 */
export async function onRequestPost(context) {
    const jose = require("jose");
    try {
        const request = context.request;
        const body = await request.formData();
        const token = body.get('cf-turnstile-response');
        const ip = request.headers.get('CF-Connecting-IP');

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
              INSERT INTO entries2 (name, email, referers, movies, remoteip, timestamp)
              VALUES (?, ?, ?, ?, ?, ?);
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
                .bind(name, email, referers, moviesString, ip, timestamp)
                .run()
            console.log('Success:', success);
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
