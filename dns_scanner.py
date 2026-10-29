import dns.resolver
import dns.exception

def get_dns_records(domain, dns_type):
    try:
        result = []
        answer = dns.resolver.resolve(domain, dns_type)

        for ans in answer:
            result.append(str(ans))
        return result

    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []

    except dns.exception.Timeout:
        print(f'Тайм-аут при запросе домена "{domain}"')
        return []

    except dns.resolver.NoNameservers:
        print(f'DNS-серверы не смогли ответить для "{domain}"')
        return []