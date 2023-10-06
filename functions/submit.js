/**
 * POST /api/submit
 */
export async function onRequestPost(context) {
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
            // NOTE: Allows multiple values per key
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
          
            let pretty = JSON.stringify(output, null, 2);
            return new Response(pretty, {
              headers: {
                'Content-Type': 'application/json;charset=utf-8',
              },
            });
          } catch (err) {
            return new Response('Error parsing JSON content', { status: 400 });
          }
        }
        catch (err) {
            return new Response(err.message || err.toString(), { status: 500 });
        }}