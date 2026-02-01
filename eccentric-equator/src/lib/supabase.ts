import { createClient } from '@supabase/supabase-js';

const supabaseUrl = 'https://yfofmawbvlontugygfcj.supabase.co';
const supabaseKey = 'sb_publishable_EFI12D4AaO2Y7o5gyWrB-g_i--T5Arz';

export const supabase = createClient(supabaseUrl, supabaseKey);
