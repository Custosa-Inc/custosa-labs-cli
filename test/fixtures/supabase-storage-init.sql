-- A minimal Supabase Storage shape for the setup SQL test (the review's supa_init.sql): the storage schema and its
-- buckets and objects tables owned by supabase_storage_admin, row-level security on, Supabase's grants to its API roles.
CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN BYPASSRLS;
CREATE ROLE supabase_storage_admin NOLOGIN;
CREATE SCHEMA storage AUTHORIZATION supabase_storage_admin;
CREATE TABLE storage.buckets (id text PRIMARY KEY, name text, owner uuid, public boolean DEFAULT false, file_size_limit bigint, allowed_mime_types text[]);
CREATE TABLE storage.objects (id uuid PRIMARY KEY, bucket_id text REFERENCES storage.buckets(id), name text, owner uuid);
ALTER TABLE storage.buckets OWNER TO supabase_storage_admin; ALTER TABLE storage.objects OWNER TO supabase_storage_admin;
ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY; ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
GRANT USAGE ON SCHEMA storage TO anon, authenticated, service_role;
GRANT ALL ON storage.buckets, storage.objects TO anon, authenticated, service_role;
INSERT INTO storage.buckets VALUES ('avatars','avatars',null,true,5242880,'{image/png}'), ('records','records',null,false,null,null);
CREATE POLICY "own files" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'records' AND owner IS NOT NULL);
