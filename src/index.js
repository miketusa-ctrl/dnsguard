import html from '../public/index.html';
import js from '../public/app.js.txt';
import css from '../public/style.css';
import genJs from '../public/generators.js.txt';
import { createApp } from './app.js';
export { KeyQuota } from './lib/quota.js'; // SQLite-backed Durable Object: per-account daily cap + shared daily pools (instance "global:budget")

const handle = createApp({ html, js, css, genJs });
export default { fetch: (req, env, ctx) => handle(req, env, ctx) };
