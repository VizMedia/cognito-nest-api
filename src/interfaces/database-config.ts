export interface DatabaseConfig {
  type: 'mysql' | 'postgres' | 'mongodb'; // Przykładowe typy baz danych
  host: string;
  port: number;
  username: string;
  password: string;
  database: string;
}
