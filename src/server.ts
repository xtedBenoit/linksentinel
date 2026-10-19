import { loadConfig } from './infrastructure/config/env.js';
import { buildApp } from './http/app.js';

async function startServer(): Promise<void> {
  const config = loadConfig();
  const app = await buildApp({ config });

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, 'Arrêt gracieux du serveur LinkSentinel...');
    await app.close();
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  try {
    await app.listen({ port: config.port, host: config.host });
  } catch (err) {
    app.log.fatal({ err }, 'Échec du démarrage du serveur HTTP');
    process.exit(1);
  }
}

void startServer();
