// /**
//  * Given an input hashmap vec and some inputs, build the inputs for a compute
//  * and chaff step and add them into the input hashmap vector
//  *
//  * @param input - reference to a vector of hashmaps containing inputs for each step of the circuit
//  * @param secret - optionally provide the secret to prove knowledge of if degree is 0
//  * @param username - optionally provide one or both usernames to hash against
//  *   - note: usernames[1] will never be 0 in practice
//  * @return - the inputs for one computation step and chaff step
//  */
// pub fn build_step_inputs(
//     input: &mut Vec<HashMap<String, Value>>,
//     secret: Option<String>,
//     usernames: [Option<String>; 2],
//     auth_secrets: [Option<Fr>; 2],
// ) {
//     // @TODO: FIX convert_phrase_to_fr and convert_username_to_fr inputs

//     // convert the compute step input to strings, or get the default value
//     let secret_input: [String; SECRET_FIELD_LENGTH] = match secret {
//         Some(phrase) => convert_phrase_to_fr(&phrase)
//             .unwrap()
//             .iter()
//             .map(|chunk| format!("0x{}", hex::encode(chunk)))
//             .collect::<Vec<String>>()
//             .try_into()
//             .unwrap(),

//         None => EMPTY_SECRET
//             .iter()
//             .map(|limb| String::from(*limb))
//             .collect::<Vec<String>>()
//             .try_into()
//             .unwrap(),
//     };
//     let usernames_input: [String; 2] = usernames
//         .iter()
//         .map(|username| match username {
//             Some(username) => format!(
//                 "0x{}",
//                 hex::encode(convert_username_to_fr(username).unwrap())
//             ),
//             None => String::from(ZERO),
//         })
//         .collect::<Vec<String>>()
//         .try_into()
//         .unwrap();
//     let auth_secrets_input: [String; 2] = auth_secrets
//         .iter()
//         .map(|auth_secret| match auth_secret {
//             Some(auth_secret) => format!("0x{}", hex::encode(auth_secret.to_bytes())),
//             None => String::from(ZERO),
//         })
//         .collect::<Vec<String>>()
//         .try_into()
//         .unwrap();

//     // build the input hashmaps
//     let mut compute_step = HashMap::new();
//     compute_step.insert("phrase".to_string(), json!(secret_input));
//     compute_step.insert("usernames".to_string(), json!(usernames_input));
//     compute_step.insert("auth_secrets".to_string(), json!(auth_secrets_input));

//     let mut chaff_step = HashMap::new();
//     chaff_step.insert("phrase".to_string(), json!(EMPTY_SECRET));
//     chaff_step.insert("usernames".to_string(), json!([ZERO, ZERO]));
//     chaff_step.insert("auth_secrets".to_string(), json!([ZERO, ZERO]));

//     // push the compute and chaff step inputs to the input vector
//     if auth_secrets[0].is_none() {
//         input.push(chaff_step.clone()); // Add initial chaff step for degree 0
//     }
//     input.push(compute_step);
//     input.push(chaff_step);
// }