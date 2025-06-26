// eslint.config.js  – vRO‑specific flat config for ESLint 9+
// Based on “vRO JavaScript Style Guide [CB10096]”

export default [
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
    },
    rules: {
      /* ----------  Style rules  ---------- */
      indent: ['error', 2, { SwitchCase: 1 }],          // 2‑space indent
      quotes: ['error', 'single', { avoidEscape: true }],// always single quotes
      semi: ['error', 'always', { omitLastInOneLineBlock: true }], // semicolon at EOL
      'brace-style': ['error', '1tbs', { allowSingleLine: true }], // { on same line
      'no-trailing-spaces': 'error',
      'no-multiple-empty-lines': [
        'error',
        { max: 1, maxBOF: 0, maxEOF: 0 },
      ],
      'keyword-spacing': ['error', { before: true, after: true }], // space after return
      'space-unary-ops': ['error', { words: true, nonwords: false }], // space after unary words

      /* ----------  Best‑practice rules  ---------- */
      eqeqeq: ['error', 'always'],          // strict equality only
      'no-use-before-define': 'error',      // declare before use
      'no-caller': 'error',                 // disallow arguments.caller / callee
      curly: ['error', 'all'],              // always use curly braces
      'no-with': 'error',                   // disallow with()
      'no-new-wrappers': 'error',           // disallow new Boolean/String/Number
      'no-inner-declarations': ['error', 'both'], // no function decls inside blocks

      /* ----------  Custom restrictions  ---------- */
      // 1) Disallow let (guide says: use var or const)
      // 2) Discourage delete (operator) – prefer setting property to null
      'no-restricted-syntax': [
        'error',
        {
          selector: "VariableDeclaration[kind='let']",
          message: 'Use var or const instead of let.',
        },
        {
          selector: "UnaryExpression[operator='delete']",
          message: 'Avoid using delete; set the property to null instead.',
        },
      ],

      /* ----------  Naming  ---------- */
      // CamelCase for variables / functions; UPPER_CASE for consts.
      camelcase: ['error', { properties: 'never', ignoreDestructuring: false }],
    },
  },
];
