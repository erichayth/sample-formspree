
/**
 * Generate a UUID from an email address using SHA-256.
 * @param {string} email - The email address.
 * @returns {string} The UUID.
 */
async function generateUUID(email) {
    // Create a SHA-256 hash of the email
    const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(email));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
    
    // Format the hash as a UUID (e.g., 8-4-4-4-12)
    return [
        hashHex.substring(0, 8),
        hashHex.substring(8, 12),
        hashHex.substring(12, 16),
        hashHex.substring(16, 20),
        hashHex.substring(20, 32)
    ].join('-');
}

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

            // Prepare SQL statement to insert data
            const sql = `
              INSERT INTO entries (uuid, name, email, referers, movies)
              VALUES (a, b, c, d, e);
            `;

            // Get data from the submitted JSON
            const { name, email, referers, movies } = output;

            // Convert movies array to a string, or serialize it in a manner suitable for your database schema
            const moviesString = JSON.stringify(movies);

            // Generate a UUID for the 'uuid' column
            const uuid = await generateUUID(email);

            // Execute SQL statement
            const { results } = await context.env.formspree_db.prepare(sql)
                .bind([uuid, name, email, referers, moviesString])
                .run();
          
            return new Response('Submission successful', {
              headers: {
                'Content-Type': 'text/plain;charset=utf-8',
              },
            });
          } catch (err) {
            return new Response('Error parsing JSON content', { status: 400 });
          }
        }
        catch (err) {
            return new Response(err.message || err.toString(), { status: 500 });
        }
}
