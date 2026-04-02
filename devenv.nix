{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  packages = [ pkgs.git ];

  languages.rust.enable = true;

  enterShell = ''
    git --version # Use packages
  '';
}
