{ lib
, config ? {}
, ... }:

let
  cfg = config.notnft or {};
  enumMode = cfg.enumMode or "normal";
  laxEnums = enumMode == "lax";
  strictEnums = enumMode == "strict";
  submodule' = { options, finalMerge ? lib.id, skipNulls ? true, freeformType ? null, chk ? null }:
  let
    reqFields = builtins.attrNames (if skipNulls then lib.filterAttrs (k: v: v.type.name != "nullOr") options else options);
    optFields = if skipNulls then builtins.attrNames (lib.filterAttrs (k: v: v.type.name == "nullOr") options) else [];
    reqFieldsDesc =
      if reqFields == [] then null
      else if builtins.length reqFields == 1 then ''field "${builtins.head reqFields}"''
      else "fields ${builtins.concatStringsSep ", " (map (x: ''"${x}"'') reqFields)}";
    optFieldsDesc =
      if optFields == [] then null
      else if builtins.length optFields == 1 then ''optional field "${builtins.head optFields}"''
      else "optional fields ${builtins.concatStringsSep ", " (map (x: ''"${x}"'') optFields)}";
  in
    submoduleWith' {
      shorthandOnlyDefinesConfig = true;
      modules = lib.toList ({
        inherit options;
      } // (if freeformType != null then {
        inherit freeformType;
      } else {}));
      description = "submodule with ${builtins.concatStringsSep " and " (builtins.filter builtins.isString [ reqFieldsDesc optFieldsDesc ])}";
      descriptionClass = "conjunction";
      chk = if chk != null then chk else x: builtins.all (optName: x?${optName}) reqFields;
      inherit finalMerge skipNulls;
    };
  # single-option submodule' (SK = single key)
  submoduleSK = key: val: submodule' {
    skipNulls = false;
    options.${key} = val;
  };
  submoduleWith' =
    { modules
    , specialArgs ? {}
    , shorthandOnlyDefinesConfig ? false
    , description ? null
    , descriptionClass ? "noun"
    , class ? null
    , finalMerge ? lib.id
    , skipNulls ? true
    , chk ? (_: true)
    }@attrs:
    let
      inherit (lib.modules) evalModules;

      allModules = defs: map ({ value, file }:
        if builtins.isAttrs value && shorthandOnlyDefinesConfig
        then { _file = file; config = value; }
        else { _file = file; imports = [ value ]; }
      ) defs;

      base = evalModules {
        inherit class specialArgs;
        modules = [{ _module.args.name = lib.mkOptionDefault "‹name›"; }] ++ modules;
      };

      freeformType = base._module.freeformType;

      name = "submodule'";

    in lib.mkOptionType {
      inherit name descriptionClass;
      description =
        if description != null then description
        else freeformType.description or name;
      check = x: builtins.isAttrs x && chk x;
      merge = loc: defs:
        lib.trace "merging" finalMerge ((if skipNulls then lib.filterAttrs (k: v: !(builtins.isNull v)) else lib.id) (base.extendModules {
          modules = [ { _module.args.name = lib.last loc; } ] ++ allModules defs;
          prefix = loc;
        }).config);
      emptyValue = { value = {}; };
      getSubOptions = prefix: (base.extendModules
        { inherit prefix; }).options // lib.optionalAttrs (freeformType != null) {
          # Expose the sub options of the freeform type. Note that the option
          # discovery doesn't care about the attribute name used here, so this
          # is just to avoid conflicts with potential options from the submodule
          _freeformOptions = freeformType.getSubOptions prefix;
        };
      getSubModules = modules;
      substSubModules = m: submoduleWith' (attrs // {
        modules = m;
      });
      nestedTypes = lib.optionalAttrs (freeformType != null) {
        freeformType = freeformType;
      };
      functor = lib.types.defaultFunctor name // {
        type = submoduleWith';
        payload = {
          inherit modules class specialArgs shorthandOnlyDefinesConfig description;
        };
        binOp = lhs: rhs: {
          class =
            # `or null` was added for backwards compatibility only. `class` is
            # always set in the current version of the module system.
            if lhs.class or null == null then rhs.class or null
            else if rhs.class or null == null then lhs.class or null
            else if lhs.class or null == rhs.class then lhs.class or null
            else debugThrow "A submoduleWith' option is declared multiple times with conflicting class values \"${toString lhs.class}\" and \"${toString rhs.class}\".";
          modules = lhs.modules ++ rhs.modules;
          specialArgs =
            let intersecting = builtins.intersectAttrs lhs.specialArgs rhs.specialArgs;
            in if intersecting == {}
            then lhs.specialArgs // rhs.specialArgs
            else debugThrow "A submoduleWith' option is declared multiple times with the same specialArgs \"${toString (builtins.attrNames intersecting)}\"";
          shorthandOnlyDefinesConfig =
            if lhs.shorthandOnlyDefinesConfig == null
            then rhs.shorthandOnlyDefinesConfig
            else if rhs.shorthandOnlyDefinesConfig == null
            then lhs.shorthandOnlyDefinesConfig
            else if lhs.shorthandOnlyDefinesConfig == rhs.shorthandOnlyDefinesConfig
            then lhs.shorthandOnlyDefinesConfig
            else debugThrow "A submoduleWith' option is declared multiple times with conflicting shorthandOnlyDefinesConfig values";
          description =
            if lhs.description == null
            then rhs.description
            else if rhs.description == null
            then lhs.description
            else if lhs.description == rhs.description
            then lhs.description
            else debugThrow "A submoduleWith' option is declared multiple times with conflicting descriptions";
        };
      };
    };

  # a custom oneOf that doesn't use `builtins.either` and has customized name/description/chk
  # also instead of just calling `chk` when merging, it properly checks whether the values merge with that type via tryEval
  oneOf' = { name, description, descriptionClass ? "noun", types, chk? (_: true) }: lib.types.mkOptionType rec {
    inherit name description descriptionClass;
    check = x: builtins.any (type: type.check x) types && chk x;
    nestedTypes = builtins.listToAttrs (lib.imap0 (i: x: { name = toString i; value = x; }) types);
    typeMerge = null;
    merge = loc: defs: lib.trace "merging"
      (let
        res = builtins.foldl'
          (x: type: if x != null then x else
            let val = lib.trace "a" builtins.tryEval (type.merge loc defs);
            in if val.success then val.value else x)
          null
          (builtins.filter (type: builtins.all ({ value, ... }: let ret = type.check value; in ret) defs) types);
      in
        if res == null
        then debugThrow "The definition of option `${lib.showOption loc}` isn't a valid ${description}. Definition values:${lib.options.showDefs defs}"
        else res);
  };

  debugThrow = s: lib.trace s /*assert s == (lib.traceVal s);*/ (throw s); # assert false; lib.trace s s.aiwddmowdim;

  types = let
    mkEnum = { name, description, enum }: lib.mkOptionType {
      inherit name description;
      descriptionClass = "noun";
      check =
        let chk = x: builtins.isAttrs x && x?__toString && x?__value__ && x?__enumName__ && (lib.trace "enum" lib.trace enum builtins.any (y: x.__value__ == y.__value__ && x.__enumName__ == y.__enumName__) (builtins.attrValues enum));
        in if strictEnums then chk
        else if laxEnums then (x: builtins.isString x || (builtins.isAttrs x && x?__toString))
        else (x: builtins.elem x (builtins.attrNames enum) || chk x);
      merge = loc: defs: lib.trace "merging enum:" lib.traceVal (lib.mergeOneOption loc (map (def: def // {
        value = toString def.value;
      }) defs));
    };
  in {
    payloadProtocol = mkEnum {
      name = "nftablesPayloadProtocol";
      description = "nftables payload protocol";
      enum = payloadProtocols;
    };
    payloadField = mkEnum {
      name = "nftablesPayloadField";
      description = "nftables payload field";
      enum = payloadFields;
    };
    rawPayloadExpression = submodule' {
      skipNulls = false;
      options.base = lib.mkOption {
        description = "Payload base.";
        type = types.payloadBase;
      };
      options.offset = lib.mkOption {
        description = "Payload offset.";
        type = lib.types.int;
      };
      options.len = lib.mkOption {
        description = "Payload length.";
        type = lib.types.int;
      };
    };
    namedPayloadExpression = submodule' {
      finalMerge = { protocol, field }@ret: lib.trace field lib.trace protocol (let
        inherit (payloadProtocols.${protocol} or {}) fields;
      in
        if laxEnums || fields?${field} then lib.trace "done" ret
        else debugThrow "Protocol ${protocol} only supports fields ${builtins.concatStringsSep ", " (builtins.attrNames fields)}");
      skipNulls = false;
      options.protocol = lib.mkOption {
        description = "Payload reference packet header protocol.";
        type = types.payloadProtocol;
      };
      options.field = lib.mkOption {
        description = "Payload reference packet header field.";
        type = types.payloadField;
      };
    };
    payloadExpression = oneOf' {
      name = "nftablesPayloadExpression";
      description = "nftables payload expression";
      types = [ types.rawPayloadExpression types.namedPayloadExpression ];
    };
    expression' = attrs: oneOf' ({
      name = "nftablesExpression";
      description = "nftables expression";
      types = lib.mapAttrsToList (k: v: submoduleSK k (lib.mkOption {
        inherit (v) type;
        description = "${k} expression.\n\n${v.description}";
      })) {
        payload = {
          type = types.payloadExpression;
          description = lib.mdDoc ''
            Construct a payload expression, i.e. a reference to a certain part of packet data. The first form creates a raw payload expression to point at a number (**len**) of bytes at a certain offset (**offset**) from a given reference point (**base**). The following base values are accepted:

            - **"ll"** - The offset is relative to Link Layer header start offset.
            - **"nh"** - The offset is relative to Network Layer header start offset.
            - **"th"** - The offset is relative to Transport Layer header start offset.

            The second form allows one to reference a field by name (**field**) in a named packet header (**protocol**).
          '';
        };
      };
    } // attrs);
    expression = types.expression' {};
  };
  # this is a function that takes a enum name and enum attrs (key = enum element, val = enum element info)
  # and for each enum element sets __enumName__ to enum name, __enum__ to enum itself, __value__ to element name,
  # __toString to a func that returns the element name, and takes enum's attrs for the rest
  mkEnum = name: attrs: let self = builtins.mapAttrs (k: v: (v // {
    __enumName__ = name;
    __enum__ = self; # removing this line resolves the issue
    __value__ = k;
    __toString = self: k;
  })) attrs; in self;
  nftTypes = mkEnum "nftTypes" {
    integer = { description = "integer"; __functor = self: bits: self // { inherit bits; }; };
    inet_service = { bits = 16; description = "internet network service"; }; # port
  };
  payloadProtocols = with nftTypes; mkEnum "payloadProtocols" {
    # removing these speeds `throw` up massively
    ether.fields = { };
    vlan.fields = { };
    arp.fields = { };
    ip.fields = { };
    icmp.fields = { };
    igmp.fields = { };
    ip6.fields = { };
    icmpv6.fields = { };
    tcp.fields = { };
    udplite.fields = { };
    dccp.fields = { };
    ah.fields = { };
    esp.fields = { };
    comp.fields = { };
    th.fields = { };

    udp.fields = {
      sport = inet_service;
      dport = inet_service;
      length = integer 16;
      checksum = integer 16;
    };
    sctp.fields = {
      sport = inet_service;
      dport = inet_service;
      vtag = integer 32;
      checksum = integer 32;
    };
  };
  payloadFields = mkEnum "payloadFields" (builtins.foldl'
    (res: field: res // { ${field} = {}; })
    {}
    (builtins.concatLists
      (map
        (x: builtins.attrNames x.fields)
        (builtins.attrValues payloadProtocols))));
in rec {
  config.notnft = {
    inherit payloadProtocols payloadFields;
    types = {
      inherit (types) expression;
    };
  };
  options.notnft = (builtins.mapAttrs (k: v: lib.mkOption { type = lib.types.unspecified; readOnly = true; }) config.notnft) // {
    enumMode = lib.mkOption {
      default = "normal";
      type = lib.types.str;
      description = lib.mdDoc ''
        Enum mode. "strict" to disallow using strings, "normal" for default behavior, "lax" to disable enum checks.
      '';
    };
  };
}
