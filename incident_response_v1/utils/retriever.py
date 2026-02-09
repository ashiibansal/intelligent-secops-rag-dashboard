def retrieve_top_incident(vectorstore, query, k=1):
    results = vectorstore.similarity_search_with_score(query, k=k)
    if not results:
        return None, None
    return results[0]
