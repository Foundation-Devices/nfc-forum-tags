{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  packages = [
    pkgs.git
    pkgs.cargo-msrv
    pkgs.cargo-sort
  ];

  languages.rust.enable = true;

  enterShell = ''
    git --version # Use packages
  '';
}
