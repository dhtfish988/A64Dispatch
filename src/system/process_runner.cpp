#include <a64dispatch/process.hpp>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
namespace a64dispatch {
namespace {
struct Descriptor {
  int value = -1;
  Descriptor() = default;
  explicit Descriptor(int supplied) : value(supplied) {}
  ~Descriptor() {
    if (value >= 0)
      ::close(value);
  }
  Descriptor(const Descriptor &) = delete;
  Descriptor &operator=(const Descriptor &) = delete;
  void close() {
    if (value >= 0) {
      ::close(value);
      value = -1;
    }
  }
};
void nonblocking(int descriptor) {
  auto flags = fcntl(descriptor, F_GETFL);
  if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0)
    throw AnalysisError("cannot set nonblocking process stream");
}
void close_on_exec(int descriptor) {
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) < 0)
    throw AnalysisError("cannot protect process descriptor");
}
struct Child {
  pid_t pid = -1;
  bool reaped = false;
  ~Child() {
    if (pid > 0) {
      kill(-pid, SIGKILL);
      if (!reaped)
        while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
        }
    }
  }
};
} // namespace
TemporaryDirectory::TemporaryDirectory() {
  auto pattern =
      (std::filesystem::temp_directory_path() / "a64dispatch-XXXXXX").string();
  std::vector<char> buffer(pattern.begin(), pattern.end());
  buffer.push_back(0);
  auto created = mkdtemp(buffer.data());
  if (!created)
    throw AnalysisError("cannot create private temporary directory");
  path_ = created;
}
TemporaryDirectory::~TemporaryDirectory() {
  std::error_code ignored;
  std::filesystem::remove_all(path_, ignored);
}
ProcessResult run_process(const std::vector<std::string> &arguments,
                          std::span<const std::uint8_t> input,
                          unsigned timeout_milliseconds,
                          std::size_t maximum_output) {
  if (arguments.empty() || arguments.size() > 256 || arguments[0].empty() ||
      timeout_milliseconds == 0 || timeout_milliseconds > 60000 ||
      maximum_output == 0 || maximum_output > 64 * 1024 * 1024 ||
      input.size() > 64 * 1024 * 1024)
    throw AnalysisError("invalid process request limits");
  for (const auto &argument : arguments)
    if (argument.size() > 1024 * 1024 ||
        argument.find('\0') != std::string::npos)
      throw AnalysisError("invalid process argument");
  int input_pair[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, input_pair) < 0)
    throw AnalysisError("cannot create child input stream");
  Descriptor input_parent(input_pair[0]), input_child(input_pair[1]);
  int output_pair[2];
  if (pipe(output_pair) < 0)
    throw AnalysisError("cannot create child output stream");
  Descriptor output_parent(output_pair[0]), output_child(output_pair[1]);
  int error_pair[2];
  if (pipe(error_pair) < 0)
    throw AnalysisError("cannot create child error stream");
  Descriptor error_parent(error_pair[0]), error_child(error_pair[1]);
  for (auto descriptor :
       {input_parent.value, input_child.value, output_parent.value,
        output_child.value, error_parent.value, error_child.value})
    close_on_exec(descriptor);
  nonblocking(input_parent.value);
  nonblocking(output_parent.value);
  nonblocking(error_parent.value);
#ifdef SO_NOSIGPIPE
  int suppress = 1;
  if (setsockopt(input_parent.value, SOL_SOCKET, SO_NOSIGPIPE, &suppress,
                 sizeof(suppress)) < 0)
    throw AnalysisError("cannot suppress stream SIGPIPE");
#endif
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attributes;
  if (posix_spawn_file_actions_init(&actions) != 0)
    throw AnalysisError("cannot initialize spawn actions");
  if (posix_spawnattr_init(&attributes) != 0) {
    posix_spawn_file_actions_destroy(&actions);
    throw AnalysisError("cannot initialize spawn attributes");
  }
  auto action_error = posix_spawn_file_actions_adddup2(
      &actions, input_child.value, STDIN_FILENO);
  action_error |= posix_spawn_file_actions_adddup2(&actions, output_child.value,
                                                   STDOUT_FILENO);
  action_error |= posix_spawn_file_actions_adddup2(&actions, error_child.value,
                                                   STDERR_FILENO);
  action_error |= posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
  action_error |= posix_spawnattr_setpgroup(&attributes, 0);
  std::vector<char *> argv;
  for (const auto &argument : arguments)
    argv.push_back(const_cast<char *>(argument.c_str()));
  argv.push_back(nullptr);
  Child child;
  auto status = action_error ? EINVAL
                             : posix_spawnp(&child.pid, argv[0], &actions,
                                            &attributes, argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  posix_spawnattr_destroy(&attributes);
  if (status) {
    child.pid = -1;
    throw AnalysisError("cannot launch process: " +
                        std::string(strerror(status)));
  }
  input_child.close();
  output_child.close();
  error_child.close();
  ProcessResult result;
  std::size_t sent = 0;
  int child_status = 0;
  auto deadline = std::chrono::steady_clock::now() +
                  std::chrono::milliseconds(timeout_milliseconds);
  auto drain = [&](Descriptor &descriptor, ByteArray &destination) {
    if (descriptor.value < 0)
      return;
    std::array<std::uint8_t, 8192> buffer{};
    for (;;) {
      auto count = read(descriptor.value, buffer.data(), buffer.size());
      if (count > 0) {
        auto size = static_cast<std::size_t>(count);
        if (size > maximum_output - destination.size())
          throw AnalysisError("process output limit exceeded");
        destination.insert(destination.end(), buffer.begin(),
                           buffer.begin() + count);
      } else if (count == 0) {
        descriptor.close();
        return;
      } else if (errno == EINTR)
        continue;
      else if (errno == EAGAIN || errno == EWOULDBLOCK)
        return;
      else
        throw AnalysisError("failed to read child output");
    }
  };
  while (!child.reaped || output_parent.value >= 0 || error_parent.value >= 0) {
    if (std::chrono::steady_clock::now() >= deadline)
      throw AnalysisError("process execution timed out");
    if (sent == input.size() && input_parent.value >= 0) {
      shutdown(input_parent.value, SHUT_WR);
      input_parent.close();
    }
    pollfd descriptors[3] = {{output_parent.value, POLLIN, 0},
                             {error_parent.value, POLLIN, 0},
                             {input_parent.value, POLLOUT, 0}};
    auto ready = poll(descriptors, 3, 10);
    if (ready < 0 && errno != EINTR)
      throw AnalysisError("process stream polling failed");
    if (input_parent.value >= 0 &&
        (descriptors[2].revents & (POLLOUT | POLLERR | POLLHUP))) {
      int flags = 0;
#ifdef MSG_NOSIGNAL
      flags = MSG_NOSIGNAL;
#endif
      auto count =
          send(input_parent.value, input.data() + sent,
               std::min<std::size_t>(input.size() - sent, 65536), flags);
      if (count > 0)
        sent += static_cast<std::size_t>(count);
      else if (count < 0 && (errno == EPIPE || errno == ECONNRESET))
        input_parent.close();
      else if (count < 0 && errno != EINTR && errno != EAGAIN &&
               errno != EWOULDBLOCK)
        throw AnalysisError("failed to write child input");
    }
    drain(output_parent, result.output);
    drain(error_parent, result.errors);
    if (!child.reaped) {
      auto ended = waitpid(child.pid, &child_status, WNOHANG);
      if (ended == child.pid)
        child.reaped = true;
      else if (ended < 0 && errno != EINTR)
        throw AnalysisError("failed to collect child status");
    }
  }
  result.exit_code =
      WIFEXITED(child_status)
          ? WEXITSTATUS(child_status)
          : 128 + (WIFSIGNALED(child_status) ? WTERMSIG(child_status) : 0);
  return result;
}
} // namespace a64dispatch
