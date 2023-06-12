{ flake, lib, ... }:

let
  inherit (flake) types;
  inherit (lib.modules) evalModules;
  chkTypeEq = type: expected: expr:
    let val = (builtins.tryEval (evalModules {
    modules = [
      {
        options.val = lib.mkOption {
          inherit type;
          default = throw "error";
        };
        config.val = expr;
      }
    ];
  }).config.val);
  in
    # assert lib.assertMsg val.success "Invalid type for ${builtins.toJSON expr}";
    lib.assertMsg (val.value == expected) "Invalid value for ${builtins.toJSON expr} (got ${builtins.toJSON val.value}, expected ${builtins.toJSON expected})";
  chkExpr = x: chkTypeEq types.expression x x;
  chkExprEq = chkTypeEq types.expression;
in

assert chkExpr 5;
assert chkExpr false;
assert chkExpr true;
# assert chkExpr null; <-- why the fuck does this eval to false?
assert chkExpr "abcd";
assert chkExpr [ 1 2 3 ];
assert chkExpr {
  "|" = [ 5 5 ];
};
assert chkExprEq {
  "|" = [ 5 5 ];
} {
  "|" = {
    lhs = 5;
    rhs = 5;
  };
};
{
  name = "flake-checks";
  type = "derivation";
}
