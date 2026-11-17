-- Derived from the flagship pg_dump (sql/schema-snapshot.sql, 2026-09-13): every CREATE POLICY
-- statement, verbatim spelling; no data. The oracle for #801.
--
-- 98 statements: 61 carry a TO clause (silent), 8 are USING (false) deny rules (silent),
-- 28 are self-scoped with no TO clause (LOW) and 1 is USING (true) with no TO clause (HIGH,
-- maintenance_message). The test derives those sets from this text; do not edit the SQL.

CREATE POLICY "Admins can delete agents" ON "public"."agents" FOR DELETE TO "authenticated" USING ("public"."is_admin"());

CREATE POLICY "Admins can delete embedding models" ON "public"."embedding_models" FOR DELETE TO "authenticated" USING ("public"."is_admin"());

CREATE POLICY "Admins can delete models" ON "public"."models" FOR DELETE TO "authenticated" USING ("public"."is_admin"());

CREATE POLICY "Admins can delete pipeline states" ON "public"."rag_pipeline_state" FOR DELETE TO "authenticated" USING ("public"."is_admin"());

CREATE POLICY "Admins can delete rate limits" ON "public"."rate_limits" FOR DELETE TO "authenticated" USING ("public"."is_admin"());

CREATE POLICY "Admins can delete subagent config" ON "public"."subagent_config" FOR DELETE USING ((EXISTS ( SELECT 1
   FROM "public"."user_profiles"
  WHERE (("user_profiles"."id" = ( SELECT "auth"."uid"() AS "uid")) AND ("user_profiles"."is_admin" = true)))));

CREATE POLICY "Admins can delete suggestions" ON "public"."initial_suggestions" FOR DELETE TO "authenticated" USING ("public"."is_admin"());

CREATE POLICY "Admins can delete widget presets" ON "public"."widget_agent_presets" FOR DELETE TO "authenticated" USING ("public"."is_admin"());

CREATE POLICY "Admins can insert agents" ON "public"."agents" FOR INSERT TO "authenticated" WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can insert conversations" ON "public"."conversations" FOR INSERT WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can insert embedding models" ON "public"."embedding_models" FOR INSERT TO "authenticated" WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can insert messages" ON "public"."messages" FOR INSERT WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can insert models" ON "public"."models" FOR INSERT TO "authenticated" WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can insert pipeline states" ON "public"."rag_pipeline_state" FOR INSERT TO "authenticated" WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can insert rate limits" ON "public"."rate_limits" FOR INSERT TO "authenticated" WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can insert requests" ON "public"."requests" FOR INSERT WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can insert subagent config" ON "public"."subagent_config" FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."user_profiles"
  WHERE (("user_profiles"."id" = ( SELECT "auth"."uid"() AS "uid")) AND ("user_profiles"."is_admin" = true)))));

CREATE POLICY "Admins can insert suggestions" ON "public"."initial_suggestions" FOR INSERT TO "authenticated" WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can insert widget presets" ON "public"."widget_agent_presets" FOR INSERT TO "authenticated" WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can read subagent config" ON "public"."subagent_config" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."user_profiles"
  WHERE (("user_profiles"."id" = ( SELECT "auth"."uid"() AS "uid")) AND ("user_profiles"."is_admin" = true)))));

CREATE POLICY "Admins can update agents" ON "public"."agents" FOR UPDATE TO "authenticated" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can update all conversations" ON "public"."conversations" FOR UPDATE USING ("public"."is_admin"());

CREATE POLICY "Admins can update all profiles" ON "public"."user_profiles" FOR UPDATE USING ("public"."is_admin"());

CREATE POLICY "Admins can update context limits" ON "public"."context_limits" FOR UPDATE TO "authenticated" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can update embedding models" ON "public"."embedding_models" FOR UPDATE TO "authenticated" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can update models" ON "public"."models" FOR UPDATE TO "authenticated" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can update pipeline states" ON "public"."rag_pipeline_state" FOR UPDATE TO "authenticated" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can update rate limits" ON "public"."rate_limits" FOR UPDATE TO "authenticated" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can update subagent config" ON "public"."subagent_config" FOR UPDATE USING ((EXISTS ( SELECT 1
   FROM "public"."user_profiles"
  WHERE (("user_profiles"."id" = ( SELECT "auth"."uid"() AS "uid")) AND ("user_profiles"."is_admin" = true))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."user_profiles"
  WHERE (("user_profiles"."id" = ( SELECT "auth"."uid"() AS "uid")) AND ("user_profiles"."is_admin" = true)))));

CREATE POLICY "Admins can update suggestions" ON "public"."initial_suggestions" FOR UPDATE TO "authenticated" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can update widget presets" ON "public"."widget_agent_presets" FOR UPDATE TO "authenticated" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());

CREATE POLICY "Admins can view all compression logs" ON "public"."context_compression_audit_logs" FOR SELECT TO "authenticated" USING ("public"."is_admin"());

CREATE POLICY "Admins can view all conversations" ON "public"."conversations" FOR SELECT USING ("public"."is_admin"());

CREATE POLICY "Admins can view all file uploads" ON "public"."file_upload_tracking" FOR SELECT TO "authenticated" USING ("public"."is_admin"());

CREATE POLICY "Admins can view all messages" ON "public"."messages" FOR SELECT USING ("public"."is_admin"());

CREATE POLICY "Admins can view all profiles" ON "public"."user_profiles" FOR SELECT USING ("public"."is_admin"());

CREATE POLICY "Admins can view all requests" ON "public"."requests" FOR SELECT USING ("public"."is_admin"());

CREATE POLICY "Admins can view pipeline states" ON "public"."rag_pipeline_state" FOR SELECT TO "authenticated" USING ("public"."is_admin"());

CREATE POLICY "Admins can view vault access logs" ON "public"."vault_access_log" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."user_profiles"
  WHERE (("user_profiles"."id" = ( SELECT "auth"."uid"() AS "uid")) AND ("user_profiles"."is_admin" = true)))));

CREATE POLICY "Allow public read agents" ON "public"."agents" FOR SELECT TO "anon" USING (("is_active" = true));

CREATE POLICY "Allow public read models" ON "public"."models" FOR SELECT TO "anon" USING (true);

CREATE POLICY "Anyone can read maintenance_message" ON "public"."maintenance_message" FOR SELECT USING (true);

CREATE POLICY "Authenticated users can read active audio files" ON "public"."audio_files" FOR SELECT TO "authenticated" USING (("is_active" = true));

CREATE POLICY "Coaches can read their own client relationships" ON "public"."coach_clients" FOR SELECT USING (("coach_id" = ( SELECT "auth"."uid"() AS "uid")));

CREATE POLICY "Deny all access to document_metadata" ON "public"."document_metadata" USING (false);

CREATE POLICY "Deny all access to documents" ON "public"."documents" USING (false);

CREATE POLICY "Deny delete for conversations" ON "public"."conversations" FOR DELETE USING (false);

CREATE POLICY "Deny delete for messages" ON "public"."messages" FOR DELETE USING (false);

CREATE POLICY "Deny delete for requests" ON "public"."requests" FOR DELETE USING (false);

CREATE POLICY "Deny delete for user_profiles" ON "public"."user_profiles" FOR DELETE USING (false);

CREATE POLICY "Only admins can change admin status" ON "public"."user_profiles" FOR UPDATE TO "authenticated" USING ("public"."is_admin"()) WITH CHECK ("public"."is_admin"());

CREATE POLICY "Service role can log vault access" ON "public"."vault_access_log" FOR INSERT TO "service_role" WITH CHECK (true);

CREATE POLICY "Service role can manage audio files" ON "public"."audio_files" TO "service_role" USING (true);

CREATE POLICY "Service role can manage token exchange attempts" ON "public"."token_exchange_attempts" TO "service_role";

CREATE POLICY "Service role can manage token exchange claims" ON "public"."token_exchange_claims" TO "service_role";

CREATE POLICY "Service role can modify maintenance_message" ON "public"."maintenance_message" TO "service_role" USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access to api_keys" ON "public"."api_keys" TO "service_role" USING (true) WITH CHECK (true);

CREATE POLICY "Service role has full access to file uploads" ON "public"."file_upload_tracking" TO "service_role" USING (true) WITH CHECK (true);

CREATE POLICY "Users can delete their own feedback" ON "public"."message_feedback" FOR DELETE USING ((( SELECT "auth"."uid"() AS "uid") = "user_id"));

CREATE POLICY "Users can insert messages in their conversations" ON "public"."messages" FOR INSERT WITH CHECK ((( SELECT "auth"."uid"() AS "uid") = "computed_session_user_id"));

CREATE POLICY "Users can insert their own conversations" ON "public"."conversations" FOR INSERT WITH CHECK ((( SELECT "auth"."uid"() AS "uid") = "user_id"));

CREATE POLICY "Users can insert their own feedback" ON "public"."message_feedback" FOR INSERT WITH CHECK ((( SELECT "auth"."uid"() AS "uid") = "user_id"));

CREATE POLICY "Users can insert their own file uploads" ON "public"."file_upload_tracking" FOR INSERT TO "authenticated" WITH CHECK ((( SELECT "auth"."uid"() AS "uid") = "user_id"));

CREATE POLICY "Users can read own profile" ON "public"."user_profiles" FOR SELECT USING ((( SELECT "auth"."uid"() AS "uid") = "id"));

CREATE POLICY "Users can update their own conversations" ON "public"."conversations" FOR UPDATE USING ((( SELECT "auth"."uid"() AS "uid") = "user_id"));

CREATE POLICY "Users can update their own feedback" ON "public"."message_feedback" FOR UPDATE USING ((( SELECT "auth"."uid"() AS "uid") = "user_id"));

CREATE POLICY "Users can update their own profile" ON "public"."user_profiles" FOR UPDATE USING ((( SELECT "auth"."uid"() AS "uid") = "id")) WITH CHECK (((( SELECT "auth"."uid"() AS "uid") = "id") AND (NOT ("is_admin" IS DISTINCT FROM false))));

CREATE POLICY "Users can view active agents" ON "public"."agents" FOR SELECT TO "authenticated" USING (("is_active" = true));

CREATE POLICY "Users can view active embedding models" ON "public"."embedding_models" FOR SELECT TO "authenticated" USING (("is_active" = true));

CREATE POLICY "Users can view active models" ON "public"."models" FOR SELECT TO "authenticated" USING (("is_active" = true));

CREATE POLICY "Users can view active suggestions" ON "public"."initial_suggestions" FOR SELECT TO "authenticated" USING (("is_active" = true));

CREATE POLICY "Users can view active widget presets" ON "public"."widget_agent_presets" FOR SELECT TO "authenticated" USING (("is_active" = true));

CREATE POLICY "Users can view context limits configuration" ON "public"."context_limits" FOR SELECT TO "authenticated" USING (true);

CREATE POLICY "Users can view rate limits" ON "public"."rate_limits" FOR SELECT TO "authenticated" USING (true);

CREATE POLICY "Users can view their own compression logs" ON "public"."context_compression_audit_logs" FOR SELECT TO "authenticated" USING ((( SELECT "auth"."uid"() AS "uid") = "user_id"));

CREATE POLICY "Users can view their own conversations" ON "public"."conversations" FOR SELECT USING ((( SELECT "auth"."uid"() AS "uid") = "user_id"));

CREATE POLICY "Users can view their own feedback" ON "public"."message_feedback" FOR SELECT USING ((( SELECT "auth"."uid"() AS "uid") = "user_id"));

CREATE POLICY "Users can view their own messages" ON "public"."messages" FOR SELECT USING ((( SELECT "auth"."uid"() AS "uid") = "computed_session_user_id"));

CREATE POLICY "Users can view their own profile" ON "public"."user_profiles" FOR SELECT USING ((( SELECT "auth"."uid"() AS "uid") = "id"));

CREATE POLICY "Users can view their own requests" ON "public"."requests" FOR SELECT USING ((( SELECT "auth"."uid"() AS "uid") = "user_id"));

CREATE POLICY "admins_delete_violations" ON "public"."guardrail_violations" FOR DELETE TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."user_profiles"
  WHERE (("user_profiles"."id" = ( SELECT "auth"."uid"() AS "uid")) AND ("user_profiles"."is_admin" = true)))));

CREATE POLICY "admins_select_violations" ON "public"."guardrail_violations" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."user_profiles"
  WHERE (("user_profiles"."id" = ( SELECT "auth"."uid"() AS "uid")) AND ("user_profiles"."is_admin" = true)))));

CREATE POLICY "audit_logs_admin_read" ON "public"."audit_logs" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."user_profiles"
  WHERE (("user_profiles"."id" = ( SELECT "auth"."uid"() AS "uid")) AND ("user_profiles"."is_admin" = true)))));

CREATE POLICY "audit_logs_allow_insert" ON "public"."audit_logs" FOR INSERT TO "authenticated" WITH CHECK ((("user_id" = ( SELECT "auth"."uid"() AS "uid")) OR ("user_id" IS NULL)));

CREATE POLICY "audit_logs_no_delete" ON "public"."audit_logs" FOR DELETE USING (false);

CREATE POLICY "audit_logs_no_modify" ON "public"."audit_logs" FOR UPDATE USING (false);

CREATE POLICY "authenticated_insert_own_violations" ON "public"."guardrail_violations" FOR INSERT TO "authenticated" WITH CHECK ((COALESCE("user_id", ''::"text") = COALESCE((( SELECT "auth"."uid"() AS "uid"))::"text", ''::"text")));

CREATE POLICY "coach_session_notes_client_select" ON "public"."coach_session_notes" FOR SELECT TO "authenticated" USING (("client_id" = ( SELECT "auth"."uid"() AS "uid")));

CREATE POLICY "coach_session_notes_coach_select" ON "public"."coach_session_notes" FOR SELECT TO "authenticated" USING (("coach_id" = ( SELECT "auth"."uid"() AS "uid")));

CREATE POLICY "couple_members_owner_select" ON "public"."couple_members" FOR SELECT TO "authenticated" USING (("user_id" = ( SELECT "auth"."uid"() AS "uid")));

CREATE POLICY "documents_1024_service_role" ON "public"."documents_1024" TO "service_role" USING (true) WITH CHECK (true);

CREATE POLICY "documents_1024_user_access" ON "public"."documents_1024" FOR SELECT TO "authenticated" USING ("public"."can_access_subdirectory"("subdirectory", ( SELECT "auth"."uid"() AS "uid"), (NULLIF(( SELECT "current_setting"('app.current_agent_id'::"text", true) AS "current_setting"), ''::"text"))::"uuid"));

CREATE POLICY "documents_1536_service_role" ON "public"."documents_1536" TO "service_role" USING (true) WITH CHECK (true);

CREATE POLICY "documents_1536_user_access" ON "public"."documents_1536" FOR SELECT TO "authenticated" USING ("public"."can_access_subdirectory"("subdirectory", ( SELECT "auth"."uid"() AS "uid"), (NULLIF(( SELECT "current_setting"('app.current_agent_id'::"text", true) AS "current_setting"), ''::"text"))::"uuid"));

CREATE POLICY "documents_service_role" ON "public"."documents" TO "service_role" USING (true) WITH CHECK (true);

CREATE POLICY "documents_user_access" ON "public"."documents" FOR SELECT TO "authenticated" USING ("public"."can_access_subdirectory"("subdirectory", ( SELECT "auth"."uid"() AS "uid"), (NULLIF(( SELECT "current_setting"('app.current_agent_id'::"text", true) AS "current_setting"), ''::"text"))::"uuid"));

CREATE POLICY "service_role_insert_any_violation" ON "public"."guardrail_violations" FOR INSERT TO "service_role" WITH CHECK (true);

CREATE POLICY "widget_token_secrets_admin_all" ON "public"."widget_token_secrets" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."user_profiles"
  WHERE (("user_profiles"."id" = ( SELECT "auth"."uid"() AS "uid")) AND ("user_profiles"."is_admin" = true)))));
