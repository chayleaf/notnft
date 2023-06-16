{ flake, lib, ... }:

let
  chkType = type: expr:
    let val = (lib.modules.evalModules {
    modules = [
      {
        options.val = lib.mkOption {
          inherit type;
        };
        config.val = expr;
      }
    ];
  }).config.val;
  in
    builtins.seq (lib.trace "evaluating val" (builtins.toJSON val)) true;
in

# at least one of those has to be an "enum"
assert chkType flake.types.expression { payload = { protocol = flake.payloadProtocols.udp; field = flake.payloadFields.vtag; }; };
{
  name = "flake-checks";
  type = "derivation";
}
