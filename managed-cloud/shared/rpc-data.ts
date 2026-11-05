/** Recovery RPC contracts return data, never capabilities. Own the received
 * result until copied, then release its RPC lifetime even if copying fails. */
export async function rpcData<T>(call: PromiseLike<T>): Promise<T> {
    const value = await call;
    try { return structuredClone(value); }
    finally {
        if (value && typeof value === 'object') {
            const disposable = value as { [Symbol.dispose]?: () => void };
            disposable[Symbol.dispose]?.();
        }
    }
}
