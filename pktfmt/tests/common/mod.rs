// Test the parse error against an error string.
#[macro_export]
macro_rules! parse_error_test {
    (   
        $file_name: expr,
        $error_msg: expr, 
        $parser: ty
    ) => {
        // The test is executed under the crate root directory.
        let mut program_path = std::env::current_dir().unwrap();
        program_path.push("tests");
        program_path.push("error_fmts");
        program_path.push($file_name);

        let file_text = ::pktfmt::file_text::FileText::new(program_path.as_path()).unwrap();
        let tokenizer = ::pktfmt::token::Tokenizer::new(file_text.text());
        let parse_res = ::pktfmt::parse_with_error!($parser, tokenizer, &file_text);

        let mut out: Vec<u8> = ::std::vec::Vec::new();
        ::pktfmt::utils::render_error(&file_text, parse_res.unwrap_err(), &mut out);
    
        assert_eq!(std::str::from_utf8(&out[..]).unwrap(), $error_msg);
    };
}