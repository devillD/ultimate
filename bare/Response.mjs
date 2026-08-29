import { OutgoingMessage } from 'node:http';
import { Stream } from 'node:stream';

/**
 * Encapsulates an HTTP response from the Bare proxy server.
 * Handles streaming chunks directly to the client's OutgoingMessage
 * with zero full-body buffering in memory.
 */
export class Response {
    headers = Object.setPrototypeOf({}, null);
    status = 200;

    /**
     * Creates a new Bare Response instance.
     * @param {Stream|Buffer|string|undefined} body - The response payload (preferably a stream for large data).
     * @param {number} status - HTTP status code (e.g., 200, 206, 403, 500).
     * @param {Object} headers - Key-value map of HTTP response headers.
     */
    constructor(body, status = 200, headers = {}) {
        this.body = body;

        if (typeof status === 'number') {
            this.status = status;
        }

        if (typeof headers === 'object' && headers !== null) {
            Object.assign(this.headers, headers);
        }
    }

    /**
     * Sends the response to the client's HTTP response object (`res`).
     * Attaches lifecycle listeners so upstream streams are closed if the client disconnects.
     *
     * @param {OutgoingMessage} clientResponse - Node.js ServerResponse object.
     * @returns {boolean} True once streaming/writing has initiated.
     */
    send(clientResponse) {
        if (!(clientResponse instanceof OutgoingMessage)) {
            throw new TypeError('Target clientResponse must be an instance of OutgoingMessage');
        }

        // If client already closed or headers were sent, safely exit
        if (clientResponse.writableEnded || clientResponse.destroyed) {
            if (this.body instanceof Stream && typeof this.body.destroy === 'function') {
                this.body.destroy();
            }
            return false;
        }

        clientResponse.writeHead(this.status, this.headers);

        if (this.body instanceof Stream) {
            // Direct pipe without buffering into V8 heap
            this.body.pipe(clientResponse);

            // If client disconnects or aborts early, destroy upstream stream
            clientResponse.on('close', () => {
                if (typeof this.body.destroy === 'function') {
                    this.body.destroy();
                }
            });

            this.body.on('error', (err) => {
                if (!clientResponse.writableEnded) {
                    clientResponse.destroy(err);
                }
            });
        } else if (Buffer.isBuffer(this.body)) {
            clientResponse.write(this.body);
            clientResponse.end();
        } else if (typeof this.body === 'string') {
            clientResponse.write(this.body);
            clientResponse.end();
        } else {
            clientResponse.end();
        }

        return true;
    }
}