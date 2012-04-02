main(int argc, char** argv) {
  setuid(0);
  setgid(0);
  return execv("./p0f", argv);
}

  